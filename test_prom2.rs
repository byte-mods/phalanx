use prometheus::{Registry, Counter};

fn main() {
    let r = Registry::new();
    let c = Counter::new("test", "test").unwrap();
    r.register(Box::new(c.clone())).unwrap();
    c.inc();
    
    for f in r.gather() {
        println!("name: {}", f.get_name()); // gets string
        for m in f.get_metric() {
            println!("counter: {:?}", m.get_counter().get_value()); // gets field
        }
    }
}
