use std::process::Command;
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = &args[1];
    if mode == "child" {
        println!("child={}", args[2]);
        eprintln!("child-stderr");
        std::process::exit(7);
    }
    let executable = &args[2];
    if mode == "missing" {
        let error = Command::new("/u8-not-present").spawn().err().unwrap();
        println!("errno={}", error.raw_os_error().unwrap());
        return;
    }
    let mut command = Command::new(executable);
    command.args(["child", "argument"]);
    match mode.as_str() {
        "spawn" => println!("status={}", command.spawn().unwrap().wait().unwrap().code().unwrap()),
        "status" => println!("status={}", command.status().unwrap().code().unwrap()),
        "output" => {
            let output = command.output().unwrap();
            println!("status={}", output.status.code().unwrap());
            print!("stdout={}", String::from_utf8(output.stdout).unwrap());
            print!("stderr={}", String::from_utf8(output.stderr).unwrap());
        }
        _ => std::process::exit(99),
    }
}
