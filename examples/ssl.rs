extern crate tiny_http;

#[cfg(not(any(
    feature = "ssl-openssl",
    feature = "ssl-rustls",
    feature = "ssl-native-tls",
    feature = "ssl-mbedtls"
)))]
fn main() {
    println!(
        "This example requires one of the supported `ssl-*` features \
         to be enabled"
    );
}

#[cfg(any(
    feature = "ssl-openssl",
    feature = "ssl-rustls",
    feature = "ssl-native-tls",
    feature = "ssl-mbedtls"
))]
fn main() {
    use tiny_http::{Response, Server};

    let mut ssl_conf =  tiny_http::SslConfig {
      certificate: include_bytes!("ssl-cert.pem").to_vec(),
      private_key: include_bytes!("ssl-key.pem").to_vec(),
    };

    ssl_conf.certificate.push(0);
    ssl_conf.private_key.push(0);

    let server = Server::https(
        "0.0.0.0:8000",
        ssl_conf
    )
    .unwrap();

    println!(
        "Note: connecting to this server will likely give you a \
         warning from your browser because the connection is \
         unsecure. This is because the certificate used by this \
         example is self-signed. With a real certificate, you \
         wouldn't get this warning."
    );

    for request in server.incoming_requests() {
        assert!(request.secure());

        println!(
            "received request! method: {:?}, url: {:?}, headers: {:?}",
            request.method(),
            request.url(),
            request.headers()
        );

        let response = Response::from_string("hello world");
        request
            .respond(response)
            .unwrap();
//            .unwrap_or(println!("Failed to respond to request"));
    }
}
