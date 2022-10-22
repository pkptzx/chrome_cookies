use clap::Parser;

/// 这里是关于,参数默认是从`Cargo.toml`获取的
#[derive(Parser, Debug)]
#[clap(name="MyApp",author, version, about, long_about = None)]
struct Args {
   /// Name of the person to greet
   #[clap(short, long, value_parser)]
   name: Vec<String>,

   /// Number of times to greet
   #[clap(short, long, value_parser, default_value_t = 1)]
   count: u8,

   /// 这里注释是命令行的提示信息
   #[clap(short='k', long, value_parser, default_value_t = 1)]
   chrome: u8,

   #[clap(short='e', long, value_parser=parse_key_val)]
   e: Vec<KeyVal>,
}

#[derive(Clone, Debug)]
struct KeyVal {
    key : String,
    val: String,
}

// 命令行不能直接转换为map
fn  parse_key_val(s: &str) ->  Result<KeyVal, String> {
    let mut str_arr = s.split("=");
    let key = str_arr.next().unwrap().to_owned();
    let val = str_arr.next().unwrap().to_owned();
    let kv = KeyVal{key,val};
    println!("{} => {:?}",s,&kv);
    Ok(kv)
}

fn main() {
   let args = Args::parse();
   
   for _ in 0..args.count {
       println!("Hello {:?}!", args)
   }
}


#[test]
fn verify_cli() {
    use clap::CommandFactory;
    Args::command().debug_assert()
}