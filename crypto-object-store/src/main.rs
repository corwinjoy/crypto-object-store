/*
Simple deltalake example using custom ObjectStore.
Adapted from delta-rs/crates/deltalake/examples/basic_operations.rs
*/

use deltalake::arrow::{
    array::{Int32Array, StringArray, TimestampMicrosecondArray},
    datatypes::{DataType as ArrowDataType, Field, Schema as ArrowSchema, TimeUnit},
    record_batch::RecordBatch,
};
use deltalake::kernel::{DataType, PrimitiveType, StructField};
use deltalake::operations::collect_sendable_stream;
use deltalake::parquet::{
    basic::{Compression, ZstdLevel},
    file::properties::WriterProperties,
};
use deltalake::{DeltaOps, protocol::SaveMode};
use std::{env, fs};

use deltalake_core::{DeltaTableBuilder, DeltaTableError};
use std::sync::Arc;
use std::time::SystemTime;
// use deltalake::storage::object_store::local::LocalFileSystem;
use url::Url;
mod crypt_fs;
use crypt_fs::CryptFileSystem;
// use log::{info, trace, warn};
use crate::crypt_fs::{KMS, KmsNone};
use log::info;
use object_store_std::DynObjectStore;
use object_store_std::local::LocalFileSystem;

fn get_table_columns() -> Vec<StructField> {
    vec![
        StructField::new(
            String::from("int"),
            DataType::Primitive(PrimitiveType::Integer),
            false,
        ),
        StructField::new(
            String::from("string"),
            DataType::Primitive(PrimitiveType::String),
            true,
        ),
        StructField::new(
            String::from("timestamp"),
            DataType::Primitive(PrimitiveType::TimestampNtz),
            true,
        ),
    ]
}

fn get_table_batches() -> RecordBatch {
    let schema = Arc::new(ArrowSchema::new(vec![
        Field::new("int", ArrowDataType::Int32, false),
        Field::new("string", ArrowDataType::Utf8, true),
        Field::new(
            "timestamp",
            ArrowDataType::Timestamp(TimeUnit::Microsecond, None),
            true,
        ),
    ]));

    let int_values = Int32Array::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    let str_values = StringArray::from(vec!["A", "B", "A", "B", "A", "A", "A", "B", "B", "A", "A"]);
    let ts_values = TimestampMicrosecondArray::from(vec![
        1000000012, 1000000012, 1000000012, 1000000012, 500012305, 500012305, 500012305, 500012305,
        500012305, 500012305, 500012305,
    ]);
    RecordBatch::try_new(
        schema,
        vec![
            Arc::new(int_values),
            Arc::new(str_values),
            Arc::new(ts_values),
        ],
    )
    .unwrap()
}

/*
   async fn test_peek_with_invalid_json() -> DeltaResult<()> {
       use crate::logstore::object_store::memory::InMemory;
       let memory_store = Arc::new(InMemory::new());
       let log_path = Path::from("delta-table/_delta_log/00000000000000000001.json");

       let log_content = r#"{invalid_json"#;

       memory_store
           .put(&log_path, log_content.into())
           .await
           .expect("Failed to write log file");

       let table_uri = "memory:///delta-table";

       let table = crate::DeltaTableBuilder::from_valid_uri(table_uri)
           .unwrap()
           .with_storage_backend(memory_store, Url::parse(table_uri).unwrap())
           .build()?;

       let result = table.log_store().peek_next_commit(0).await;
       assert!(result.is_err());
       Ok(())
   }
*/

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), deltalake::errors::DeltaTableError> {
    use log::LevelFilter;
    simple_logging::log_to_file("crypt_fs.log", LevelFilter::Trace)?;

    let workdir = env::current_dir()?;
    let dir = "/test_crypt";
    let path = String::from(workdir.to_str().unwrap()) + dir;
    let path = path.as_str();
    let joined = String::from("file://") + path;
    let table_uri = joined.as_str();

    let _ = fs::remove_dir_all(path);
    fs::create_dir(path)?;
    
    let kms = Arc::new(KmsNone::new());
    let encrypted_file_store = Arc::new(CryptFileSystem::new(table_uri, kms)?);
    timed_delta_table_read_write("ObjectStore with **NO** Encryption", path, table_uri, encrypted_file_store)
        .await
        .expect("Error in encrypted read/write");

    let kms = Arc::new(KMS::new(b"password"));
    let encrypted_file_store = Arc::new(CryptFileSystem::new(table_uri, kms)?);
    timed_delta_table_read_write("ObjectStore with Encryption", path, table_uri, encrypted_file_store)
        .await
        .expect("Error in encrypted read/write");

    let file_store = Arc::new(LocalFileSystem::new_with_prefix(path)?);
    timed_delta_table_read_write("Raw LocalFileSystem", path, table_uri, file_store)
        .await
        .expect("Error in encrypted read/write");
    Ok(())
}

async fn timed_delta_table_read_write(
    label: &str,
    path: &str,
    table_uri: &str,
    object_store: Arc<DynObjectStore>,
) -> Result<(), deltalake::errors::DeltaTableError> {
    let now = SystemTime::now();

    delta_table_read_write(path, table_uri, object_store).await??;

    println!("\n****************************************************************************\n");
    match now.elapsed() {
        Ok(elapsed) => {
            println!("{} time: {}ms", label, elapsed.as_millis());
        }
        Err(e) => {
            // an error occurred!
            println!("Timer Error: {e:?}");
        }
    }
    println!("\n****************************************************************************\n");

    Ok(())
}

async fn delta_table_read_write(
    path: &str,
    table_uri: &str,
    object_store: Arc<DynObjectStore>,
) -> Result<Result<(), DeltaTableError>, DeltaTableError> {
    let _ = fs::remove_dir_all(path);
    fs::create_dir(path)?;
    
    info!("start DeltaTableBuilder::build");

    let mut table = DeltaTableBuilder::from_valid_uri(table_uri)
        .unwrap()
        .with_storage_backend(object_store, Url::parse(table_uri).unwrap())
        .build()?;

    info!("finish DeltaTableBuilder::build");

    // Create a delta operations client pointing at an un-initialized location.
    // We allow for uninitialized locations, since we may want to create the table
    info!("start table.load");
    let ops: DeltaOps = match table.load().await {
        Ok(_) => Ok(table.into()),
        Err(DeltaTableError::NotATable(_)) => Ok(table.into()),
        Err(err) => Err(err),
    }?;
    info!("finish table.load");

    // The operations module uses a builder pattern that allows specifying several options
    // on how the command behaves. The builders implement `Into<Future>`, so once
    // options are set you can run the command using `.await`.
    info!("start table.create");
    let table = ops
        .create()
        .with_columns(get_table_columns())
        .with_partition_columns(["timestamp"])
        .with_table_name("my_table")
        .with_comment("A table to show how delta-rs works")
        .await?;
    info!("finish table.create");

    assert_eq!(table.version(), 0);

    let writer_properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(3).unwrap()))
        .build();

    let batch = get_table_batches();
    info!("start table.write");
    let table = DeltaOps(table)
        .write(vec![batch.clone()])
        .with_writer_properties(writer_properties)
        .await?;
    info!("finish table.write");

    assert_eq!(table.version(), 1);

    let writer_properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(3).unwrap()))
        .build();

    // To overwrite instead of append (which is the default), use `.with_save_mode`:
    info!("start table.write append");
    let table = DeltaOps(table)
        .write(vec![batch.clone()])
        .with_save_mode(SaveMode::Overwrite)
        .with_writer_properties(writer_properties)
        .await?;
    info!("finish table.write append");

    assert_eq!(table.version(), 2);

    info!("start table.load");
    let (_table, stream) = DeltaOps(table).load().await?;
    let data: Vec<RecordBatch> = collect_sendable_stream(stream).await?;
    info!("finish table.load");

    println!("{data:?}");

    Ok(Ok(()))
}
