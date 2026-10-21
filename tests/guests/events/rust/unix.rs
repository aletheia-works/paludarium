use std::io::{Read, Write};
fn main() {
    let (mut a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
    a.write_all(b"hello").unwrap();
    let mut data = [0; 5];
    b.read_exact(&mut data).unwrap();
    assert_eq!(&data, b"hello");
    b.write_all(b"world").unwrap();
    a.read_exact(&mut data).unwrap();
    assert_eq!(&data, b"world");
    println!("unix:PASS");
}
