use std::path::PathBuf;
use ethereum_types::Address;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "ZKT tools", version = "0.1.0", about = "Helpful tools of ZKT protocol")]
enum Args {
    SetupKZG {
        #[arg(long = "max-degree", default_value = "1 << 20")]
        max_degree: usize,
        #[arg(long, short = 's')]
        seed: Option<String>,
        #[arg(long = "universal-path", default_value = "../data/universal")]
        universal_path: PathBuf,
    },
    Compile {
        #[arg(long = "table-size", default_value = "1024")]
        table_size: usize,
        #[arg(long = "universal-path", default_value = "../data/universal")]
        universal_path: PathBuf,
        #[arg(long = "ck-path", default_value = "../data/ck")]
        ck_path: PathBuf,
        #[arg(long = "cvk-path", default_value = "../data/cvk")]
        cvk_path: PathBuf,
        #[arg(long = "pk-path", default_value = "../data/pk")]
        pk_path: PathBuf,
        #[arg(long = "epk-path", default_value = "../data/epk")]
        epk_path: Option<PathBuf>,
        #[arg(long = "vk-path", default_value = "../data/vk")]
        vk_path: PathBuf,
    },
    Prove {
        #[arg(long = "ck-path", default_value = "../data/ck")]
        ck_path: PathBuf,
        #[arg(long = "pk-path", default_value = "../data/pk")]
        pk_path: PathBuf,
        #[arg(long = "epk-path", default_value = "../data/epk")]
        epk_path: Option<PathBuf>,
        #[arg(long = "vk-path", default_value = "../data/vk")]
        vk_path: PathBuf,
        #[arg(long, short = 'w')]
        whitelist: Vec<String>,
        #[arg(long, short = 's')]
        seed: Option<String>,
        #[arg(long = "witness-path", default_value = "../data/witness")]
        witness_path: PathBuf,
    },
}


fn main() {

}
