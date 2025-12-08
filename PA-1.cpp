#include <iostream>
#include <cmath>
#include <limits>
#include <climits>

using namespace std;

class PrimeComputer {
public:

    // Safe factorial up to 20! (fits in unsigned long long)
    unsigned long long factorial(int k) {
        if (k < 0 || k > 20) return ULLONG_MAX;
        unsigned long long res = 1;
        for (int i = 2; i <= k; i++) {
            res *= i;
        }
        return res;
    }

    // Wilson-based prime detector F(j)
    // F(j) = floor(cos^2(pi * ((j-1)! + 1)/j))
    int F(int j) {
        if (j == 1) return 1;

        // factorial overflows after 20
        if (j - 1 > 20) return 0;

        unsigned long long fact = factorial(j - 1);
        long double argument = (long double)(fact + 1) / j;

        long double cos_val = cos(M_PI * argument);
        long double result = floor(cos_val * cos_val);

        return (int)result;
    }

    // Willans’ Formula: nth prime
    int getNthPrime(int n) {
        if (n <= 0) {
            cout << "n must be positive." << endl;
            return -1;
        }

        // Compute 2^n safely
        int limit = 1 << n;

        long double total_sum = 0;
        int S_i = 0;   // cumulative sum of F(j)

        for (int i = 1; i <= limit; i++) {
            S_i += F(i);    // efficiently update S(i) = S(i-1) + F(i)

            // Willans term = floor( (n / (1 + S(i)))^(1/n) )
            long double denom = 1.0L + S_i;
            long double term = pow(n / denom, 1.0L / n);

            total_sum += floor(term);
        }

        return 1 + (int)total_sum;
    }
};

int main() {
    PrimeComputer pc;

    int test_vals[] = {1, 2, 3, 4};

    for (int n : test_vals) {
        int p = pc.getNthPrime(n);
        cout << "The " << n << "-th prime is: " << p << endl;
        cout << "--------------------------------------\n";
    }

    cout << "Note: Willans' Formula becomes unusable for n >= 5\n"
         << "because it needs factorials up to 2^n!, which overflow\n"
         << "and the expression becomes computationally impossible.\n";

    return 0;
}
