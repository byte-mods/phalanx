use prometheus::{Registry, Counter};

fn main() {
    let r = Registry::new();
    let c = Counter::new("test", "test").unwrap();
    r.register(Box::new(c)).unwrap();
    let families = r.gather();
    for f in families {
        for m in f.get_metric() {
            if m.get_counter().is_some() {
                println!("{:?}", m.get_counter().value());
            }
        }
    }
}
