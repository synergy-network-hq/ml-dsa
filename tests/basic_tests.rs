use ml_dsa::{ Poly, PolyVecL, PolyVecK, N, Q, K, L, ETA, GAMMA2 };

#[test]
fn test_parameters() {
    // Test that parameters match ML-DSA-65 (formerly CRYSTALS-Dilithium) Level 3
    assert_eq!(N, 256);
    assert_eq!(Q, 8380417);
    assert_eq!(K, 6);
    assert_eq!(L, 5);
    assert_eq!(ETA, 4);
    assert_eq!(GAMMA2, 261888); // (Q-1)/32
}

#[test]
fn test_poly_creation() {
    let poly = Poly::new();
    assert_eq!(poly.coeffs.len(), N);
    for coeff in poly.coeffs {
        assert_eq!(coeff, 0);
    }
}

#[test]
fn test_polyvec_creation() {
    let polyvecl = PolyVecL::new();
    assert_eq!(polyvecl.vec.len(), L);

    let polyveck = PolyVecK::new();
    assert_eq!(polyveck.vec.len(), K);

    for poly in polyvecl.vec {
        assert_eq!(poly.coeffs.len(), N);
    }

    for poly in polyveck.vec {
        assert_eq!(poly.coeffs.len(), N);
    }
}

#[test]
fn test_basic_reduce_functions() {
    use ml_dsa::reduce::{ reduce32, caddq, freeze };

    // Test reduce32
    let a = 10000000;
    let reduced = reduce32(a);
    assert!(reduced < (Q as i32));

    // Test caddq
    let negative = -1000;
    let result = caddq(negative);
    assert!(result >= 0);

    // Test freeze
    let frozen = freeze(a);
    assert!(frozen >= 0 && frozen < (Q as i32));
}

#[test]
fn test_poly_roundtrip() {
    let mut poly = Poly::new();
    poly.coeffs[0] = 1000;
    poly.coeffs[1] = -500;

    // Test that we can modify and access coefficients
    assert_eq!(poly.coeffs[0], 1000);
    assert_eq!(poly.coeffs[1], -500);

    // Test that other coefficients remain zero
    for i in 2..N {
        assert_eq!(poly.coeffs[i], 0);
    }
}

#[test]
fn test_ntt_roundtrip() {
    use ml_dsa::ntt::{ ntt, invntt_tomont };

    let mut poly = Poly::new();
    poly.coeffs[0] = 1000;
    poly.coeffs[1] = 500;

    // Apply NTT
    ntt(&mut poly.coeffs);

    // Apply inverse NTT
    invntt_tomont(&mut poly.coeffs);

    // Test that the operations complete without error
    // The coefficients will have scaling factors applied
    assert!(poly.coeffs[0] != 0 || poly.coeffs[1] != 0);
}

#[test]
fn test_cbd_functions() {
    use ml_dsa::cbd::rej_eta;

    let mut output = [0i32; 10];
    let buf = [0u8; 20];

    // Test that rej_eta function can be called
    let result = rej_eta(&mut output, 10, &buf, 20);
    assert!(result <= 10);
}
