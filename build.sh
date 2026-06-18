#!/bin/bash
# =====================================================================
#   build.sh  —  Blockchain Voting System Builder
#   Compiles all four executables (core, admin, agent, voter)
#   OpenSSL path: F:/software/Blockchain/openssl_extracted/mingw64
# =====================================================================
set -e

echo ">>> Building Blockchain Voting System v2.0 ..."

GPP="g++"
INC="F:/software/Blockchain/openssl_extracted/mingw64/include"
LIB="F:/software/Blockchain/openssl_extracted/mingw64/lib"
FLAGS="-std=c++17 -I$INC -L$LIB -lssl -lcrypto -lws2_32 -lgdi32 -lcrypt32 -O2"

echo "[1/4] Building core.exe  ..."
$GPP core.cpp  -o core.exe  $FLAGS

echo "[2/4] Building admin.exe ..."
$GPP admin.cpp -o admin.exe $FLAGS

echo "[3/4] Building agent.exe ..."
$GPP agent.cpp -o agent.exe $FLAGS

echo "[4/4] Building voter.exe ..."
$GPP voter.cpp -o voter.exe $FLAGS

echo ""
echo ">>> Build complete! Run in this order:"
echo "  1. admin.exe   -> Load voter file + add candidates"
echo "  2. voter.exe   -> Voter registration"
echo "  3. agent.exe   -> Issue OTP for the voter"
echo "  4. voter.exe   -> Voter login + cast vote"
echo "  5. admin.exe   -> View live results"