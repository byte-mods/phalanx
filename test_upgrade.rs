use hyper::{Request, Response, body::Incoming};

fn test_upgrade(req: &mut Request<Incoming>, res: &mut Response<Incoming>) {
    let client_upgrade = hyper::upgrade::on(req);
    let server_upgrade = hyper::upgrade::on(res);
}
