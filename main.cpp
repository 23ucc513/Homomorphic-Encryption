#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

// Requires Microsoft SEAL installed and available on the include/link paths.
// Compile example:
//   g++ -std=c++17 main.cpp -I/path/to/seal/include -L/path/to/seal/lib -lseal -o hpw

#include "seal/seal.h"

using namespace std;
using namespace seal;

// Read CSV, extract temperature and rainfall (0/1), skipping header.
// Only keeps up to max_rows rows.
void read_weather_csv(
    const string &path,
    vector<double> &temperatures,
    vector<double> &rainfall,
    size_t max_rows = 100)
{
    ifstream in(path);
    if (!in.is_open())
    {
        throw runtime_error("Failed to open file: " + path);
    }

    string line;

    // Read header row
    if (!getline(in, line))
    {
        throw runtime_error("CSV file is empty");
    }

    size_t rows = 0;
    while (rows < max_rows && getline(in, line))
    {
        if (line.empty())
        {
            continue;
        }

        stringstream ss(line);
        string token;

        // The dataset columns are in this assumed order:
        // Formatted Date, Summary, Precip Type, Temperature (C), Apparent Temperature (C), Humidity,
        // Wind Speed (km/h), Wind Bearing, Visibility (km), Cloud Cover, Pressure (millibars), ...
        // We only need Precip Type (index 2) and Temperature (index 3).

        vector<string> cols;
        while (getline(ss, token, ','))
        {
            cols.push_back(token);
        }

        // Expect at least 5 columns to have the temperature value.
        if (cols.size() < 5)
        {
            continue; // invalid/short row
        }

        string precip_type = cols[2];
        string temp_str = cols[3];

        // Sanitize values
        if (temp_str.empty())
        {
            continue;
        }

        double temp_val;
        try
        {
            temp_val = stod(temp_str);
        }
        catch (const exception &)
        {
            continue;
        }

        double rain_val = 0.0;
        if (!precip_type.empty())
        {
            // Treat "rain" (case-insensitive) as rainfall
            string precip_lower = precip_type;
            for (auto &c : precip_lower)
                c = static_cast<char>(tolower(c));
            if (precip_lower == "rain")
            {
                rain_val = 1.0;
            }
        }

        temperatures.push_back(temp_val);
        rainfall.push_back(rain_val);
        rows++;
    }
}

int main()
{
    try
    {
        const string csv_path = "data/weatherHistory.csv";

        vector<double> temperatures;
        vector<double> rainfall;

        read_weather_csv(csv_path, temperatures, rainfall, 100);

        if (temperatures.empty() || rainfall.empty())
        {
            cerr << "No valid data parsed from CSV." << endl;
            return 1;
        }

        if (temperatures.size() != rainfall.size())
        {
            cerr << "Parsed data vectors have mismatched lengths." << endl;
            return 1;
        }

        size_t n = temperatures.size();
        if (n == 0)
        {
            cerr << "No rows available after filtering." << endl;
            return 1;
        }

        cout << "Parsed " << n << " rows (max 100)." << endl;

        // Keep a small plaintext reference for sanity checking results
        double plain_sum_temp = 0.0;
        double plain_sum_rain = 0.0;
        for (size_t i = 0; i < n; ++i)
        {
            plain_sum_temp += temperatures[i];
            plain_sum_rain += rainfall[i];
        }
        double plain_avg_temp = plain_sum_temp / static_cast<double>(n);

        // SEAL setup (CKKS)
        EncryptionParameters parms(scheme_type::ckks);
        size_t poly_modulus_degree = 8192;
        parms.set_poly_modulus_degree(poly_modulus_degree);
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));

        // Construct SEALContext directly (older/public API does not have Create())
        SEALContext context(parms);

        KeyGenerator keygen(context);
        SecretKey secret_key = keygen.secret_key();

        PublicKey public_key;
        keygen.create_public_key(public_key);

        RelinKeys relin_keys;
        keygen.create_relin_keys(relin_keys);

        // For vector rotations (sum + trend), generate the necessary Galois keys.
        // We generate keys for all required rotation steps up to n-1 (n <= 100).
        GaloisKeys gal_keys;
        {
            vector<int> rotation_steps;
            rotation_steps.reserve(n);
            for (size_t i = 1; i < n; ++i)
            {
                rotation_steps.push_back(static_cast<int>(i));
            }
            keygen.create_galois_keys(rotation_steps, gal_keys);
        }

        Encryptor encryptor(context, public_key);
        Evaluator evaluator(context);
        Decryptor decryptor(context, secret_key);
        CKKSEncoder encoder(context);

        double scale = pow(2.0, 40);

        // Encode and encrypt vectors
        Plaintext pt_temps;
        Plaintext pt_rain;
        encoder.encode(temperatures, scale, pt_temps);
        encoder.encode(rainfall, scale, pt_rain);

        Ciphertext ct_temps;
        Ciphertext ct_rain;
        encryptor.encrypt(pt_temps, ct_temps);
        encryptor.encrypt(pt_rain, ct_rain);

        // Helper: compute sum of a vector stored in a ciphertext using power-of-two rotations
        auto sum_encrypted_vector = [&](const Ciphertext &ct) {
            // Sum the first `n` slots by rotating the original ciphertext by each
            // index offset and accumulating. This avoids double-counting when `n`
            // is not a power of two.
            Ciphertext running = ct;
            for (size_t i = 1; i < n; ++i)
            {
                Ciphertext rotated;
                evaluator.rotate_vector(ct, static_cast<int>(i), gal_keys, rotated);
                evaluator.add_inplace(running, rotated);
            }
            return running;
        };

        // Part 4.1: Average temperature
        Ciphertext ct_sum_temp = sum_encrypted_vector(ct_temps);
        double inv_n = 1.0 / static_cast<double>(n);
        Plaintext pt_inv_n;
        encoder.encode(inv_n, scale, pt_inv_n);
        evaluator.multiply_plain_inplace(ct_sum_temp, pt_inv_n);
        evaluator.rescale_to_next_inplace(ct_sum_temp);

        // Part 4.2: Total rainfall
        Ciphertext ct_sum_rain = sum_encrypted_vector(ct_rain);

        // Part 4.3: Temperature trend (t[i+1] - t[i])
        Ciphertext ct_temps_rot;
        evaluator.rotate_vector(ct_temps, 1, gal_keys, ct_temps_rot);
        Ciphertext ct_trend;
        evaluator.sub(ct_temps_rot, ct_temps, ct_trend);

        // Decrypt and decode results
        Plaintext pt_avg_temp;
        Plaintext pt_total_rain;
        Plaintext pt_trend;

        decryptor.decrypt(ct_sum_temp, pt_avg_temp);
        decryptor.decrypt(ct_sum_rain, pt_total_rain);
        decryptor.decrypt(ct_trend, pt_trend);

        vector<double> avg_temp_res;
        vector<double> total_rain_res;
        vector<double> trend_res;

        encoder.decode(pt_avg_temp, avg_temp_res);
        encoder.decode(pt_total_rain, total_rain_res);
        encoder.decode(pt_trend, trend_res);

        // Output
        cout << fixed;
        cout << "HE average temperature (slot 0): " << avg_temp_res[0] << " C" << endl;
        cout << "Plain average temperature:     " << plain_avg_temp << " C" << endl;

        cout << "HE total rainfall (slot 0): " << total_rain_res[0] << " (rain count)" << endl;
        cout << "Plain total rainfall:        " << plain_sum_rain << " (rain count)" << endl;

        cout << "\nTemperature trend (first 10 values of t[i+1]-t[i]):" << endl;
        for (size_t i = 0; i + 1 < n && i < 10; ++i)
        {
            cout << "  " << i << ": " << trend_res[i] << "\n";
        }
        cout << "(Note: last slot is wrap-around due to vector rotation and should be ignored.)" << endl;

        return 0;
    }
    catch (const exception &ex)
    {
        cerr << "Error: " << ex.what() << endl;
        return 1;
    }
}
