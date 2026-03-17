#include <seal/seal.h>
#include <iostream>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

int main()
{
    cout << "==== CKKS Encrypted Calculator (Debug Mode) ====\n\n";

    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(
        CoeffModulus::Create(poly_modulus_degree,{60,40,40,60}));

    SEALContext context(parms);

    cout << "Poly modulus degree: " << poly_modulus_degree << endl;

    KeyGenerator keygen(context);

    PublicKey public_key;
    keygen.create_public_key(public_key);

    SecretKey secret_key = keygen.secret_key();

    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);

    double scale = pow(2.0,40);

    cout << "Scale: " << scale << endl << endl;

    double a,b;
    int op;

    cout << "Enter first number: ";
    cin >> a;

    cout << "Enter second number: ";
    cin >> b;

    cout << "\nChoose operation:\n1 → Add\n2 → Multiply\n";
    cin >> op;

    cout << "\n--- Encoding Step ---\n";

    Plaintext plain1, plain2;

    encoder.encode(a,scale,plain1);
    encoder.encode(b,scale,plain2);

    cout << "Plaintext 1 (scaled): " << plain1 << endl;
    cout << "Plaintext 2 (scaled): " << plain2 << endl;

    cout << "\n--- Encryption Step ---\n";

    Ciphertext enc1, enc2;

    encryptor.encrypt(plain1,enc1);
    encryptor.encrypt(plain2,enc2);

    cout << "Ciphertext1 size: " << enc1.size() << endl;
    cout << "Ciphertext2 size: " << enc2.size() << endl;

    Ciphertext result;

    cout << "\n--- Evaluation Step ---\n";

    if(op == 1)
    {
        evaluator.add(enc1,enc2,result);
        cout << "Performed encrypted addition\n";
    }
    else if(op == 2)
    {
        evaluator.multiply(enc1,enc2,result);

        cout << "After multiplication ciphertext size: "
             << result.size() << endl;

        evaluator.rescale_to_next_inplace(result);

        cout << "Rescaling performed\n";
    }
    else
    {
        cout << "Invalid operation\n";
        return 0;
    }

    cout << "\n--- Decryption Step ---\n";

    Plaintext plain_result;

    decryptor.decrypt(result,plain_result);

    cout << "Decrypted polynomial: " << plain_result << endl;

    vector<double> output;

    encoder.decode(plain_result,output);

    cout << "\nFinal decoded result: " << output[0] << endl;

    return 0;
}