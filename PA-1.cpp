/**
 * Programming Assignment 1: Willans' Formula Implementation
 * * Description:
 * This program implements Willans' Formula to compute the n-th prime number.
 * The formula transforms Wilson's Theorem (a prime detector) into a prime computer.
 */

#include <iostream>
#include <cmath>
#include <vector>

// Using long double for higher precision with trigonometric functions
// Using unsigned long long for factorials (fits up to 20!)
using namespace std;

class PrimeComputer {
public:
    // Helper function to calculate factorial
    unsigned long long factorial(int k) {
        if (k < 0) return 0; // Should not happen in this formula
        unsigned long long res = 1;
        for (int i = 2; i <= k; i++) {
            res *= i;
        }
        return res;
    }

    // The Prime Detector F(j) derived from Wilson's Theorem
    // F(j) = floor(cos^2(pi * ((j-1)! + 1) / j))
    // Returns 1 if j is prime (or 1), 0 otherwise.
    int F(int j) {
        if (j == 1) return 1; // Formula convention: F(1)=1

        // Calculate the argument: ((j-1)! + 1) / j
        unsigned long long fact = factorial(j - 1);
        long double argument = (long double)(fact + 1) / j;
        
        // Apply trigonometric detector
        long double cos_val = cos(argument * M_PI);
        long double result = floor(cos_val * cos_val);
        
        return (int)result;
    }

    // Willans' Formula to find the n-th prime
    // p_n = 1 + sum_{i=1}^{2^n} floor( (n / S(i))^(1/n) )
    int getNthPrime(int n) {
        if (n <= 0) {
            cout << "n must be a positive integer." << endl;
            return -1;
        }

        // Limit is 2^n
        int limit = pow(2, n);
        long double total_sum = 0;
        int current_S_i = 0;

        cout << "Computing " << n << "-th prime. Loop range i = 1 to " << limit << "..." << endl;

        // Outer summation over i
        for (int i = 1; i <= limit; i++) {
            
            // Inner summation S(i) = sum_{j=1}^{i} F(j)
            // We can optimize by adding F(i) to the previous S(i-1)
            current_S_i += F(i);

            // Threshold term: floor( (n / S(i))^(1/n) )
            // If S(i) is 0 (should not happen for i>=1), handle gracefully
            long double term = 0;
            if (current_S_i > 0) {
                term = floor(pow((long double)n / current_S_i, 1.0 / n));
            }
            
            total_sum += term;
        }

        return 1 + (int)total_sum;
    }
};

int main() {
    PrimeComputer pc;
    
    // Test cases allowed by standard data types (n=1 to 4)
    int test_vals[] = {1, 2, 3, 4};
    
    for (int n : test_vals) {
        int p_n = pc.getNthPrime(n);
        cout << "The " << n << "-th prime is: " << p_n << endl;
        cout << "---------------------------------------" << endl;
    }

    cout << "Note: For n >= 5, integer overflow occurs with standard types " 
         << "because the formula requires (2^n - 1)!." << endl;

    return 0;
}