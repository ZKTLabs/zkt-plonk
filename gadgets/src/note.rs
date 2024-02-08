use ark_ff::Field;

struct ULO<A, F: Field> {
    index: usize,
    amount: A,
    secret: F,
}

struct Note<A, F: Field> {
    identifier: F,
    ulos: Vec<ULO<A, F>>,
}
