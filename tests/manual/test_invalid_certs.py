#!/usr/bin/env python3
"""Test certificate validation by trying to connect with invalid certificates."""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.client import SecureChatClient


def test_rogue_cert():
    """Test 1: Self-signed certificate (not signed by CA)."""
    print("\n" + "="*70)
    print("TEST 1: Self-Signed Certificate (Not Signed by CA)")
    print("="*70)
    
    # Temporarily replace client cert with rogue cert
    import shutil
    shutil.copy("certs/alice-cert.pem", "certs/alice-cert.pem.backup")
    shutil.copy("certs/alice-key.pem", "certs/alice-key.pem.backup")
    shutil.copy("certs/rogue-cert.pem", "certs/alice-cert.pem")
    shutil.copy("certs/rogue-key.pem", "certs/alice-key.pem")
    
    try:
        client = SecureChatClient("localhost", 5000, username="alice")
        client.connect()
        
        if not client._certificate_exchange():
            print("\n PASS: Server rejected rogue certificate (expected BAD_CERT)")
        else:
            print("\n FAIL: Server accepted rogue certificate (security issue!)")
            
    except Exception as e:
        print(f"\n PASS: Connection failed with rogue cert: {e}")
    finally:
        # Restore original cert
        shutil.move("certs/alice-cert.pem.backup", "certs/alice-cert.pem")
        shutil.move("certs/alice-key.pem.backup", "certs/alice-key.pem")


def test_expired_cert():
    """Test 2: Expired certificate."""
    print("\n" + "="*70)
    print("TEST 2: Expired Certificate")
    print("="*70)
    
    # Temporarily replace client cert with expired cert
    import shutil
    shutil.copy("certs/alice-cert.pem", "certs/alice-cert.pem.backup")
    shutil.copy("certs/alice-key.pem", "certs/alice-key.pem.backup")
    shutil.copy("certs/expired-cert.pem", "certs/alice-cert.pem")
    shutil.copy("certs/expired-key.pem", "certs/alice-key.pem")
    
    try:
        client = SecureChatClient("localhost", 5000, username="alice")
        client.connect()
        
        if not client._certificate_exchange():
            print("\n PASS: Server rejected expired certificate (expected BAD_CERT)")
        else:
            print("\n FAIL: Server accepted expired certificate (security issue!)")
            
    except Exception as e:
        print(f"\n PASS: Connection failed with expired cert: {e}")
    finally:
        # Restore original cert
        shutil.move("certs/alice-cert.pem.backup", "certs/alice-cert.pem")
        shutil.move("certs/alice-key.pem.backup", "certs/alice-key.pem")


def main():
    print("\nCertificate Validation Security Tests")
    print("These tests verify that invalid certificates are properly rejected.\n")
    
    # Check if server is running
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(("localhost", 5000))
        sock.close()
    except:
        print(" ERROR: Server not running!")
        print("   Please start the server first: python -m app.server")
        return
    
    # Run tests
    test_rogue_cert()
    test_expired_cert()
    
    print("\n" + "="*70)
    print("Certificate validation tests complete!")
    print("="*70)


if __name__ == "__main__":
    main()
