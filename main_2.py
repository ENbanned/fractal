"""Complete example of Fractal Bitcoin library usage."""

import asyncio
from fractal import connect, Network
from fractal.crypto import PrivateKey, generate_mnemonic


async def main():
    """Demonstrate all key features."""
    
    print("=== Fractal Bitcoin Library Demo ===\n")
    
    # 1. Generate new wallet
    print("1. Creating new wallet with mnemonic...")
    mnemonic = generate_mnemonic(strength=128)  # 12 words
    print(f"Mnemonic: {mnemonic}")
    print("⚠️  Save this mnemonic securely!\n")
    
    # 2. Connect to Fractal Bitcoin
    async with connect(network=Network.MAINNET) as client:
        
        # 3. Create wallet
        wallet = client.wallet.create_wallet("DemoWallet")
        
        # 4. Create account from mnemonic
        account = wallet.create_account_from_mnemonic(
            mnemonic=mnemonic,
            label="Main Account"
        )
        
        print(f"2. Wallet created successfully!")
        print(f"   Address: {account.address}")
        print(f"   Type: {account.address_type}\n")
        
        # 5. Show all address formats
        print("3. All address formats (same private key):")
        print(f"   P2PKH (Legacy):     {account.p2pkh_address}")
        print(f"   P2WPKH (SegWit):    {account.p2wpkh_address}")
        print(f"   P2TR (Taproot):     {account.p2tr_address}\n")
        
        # 6. Export private key
        wif = account.export_private_key()
        print(f"4. Private key (WIF): {wif}")
        print("   ⚠️  Keep this private!\n")
        
        # 7. Check balance
        try:
            balance = await account.get_balance()
            print(f"5. Balance: {balance} sats ({balance / 100_000_000:.8f} FB)\n")
        except:
            print("5. Balance check skipped (no connection)\n")
    
    # 8. Import into UniSat
    print("6. To import into UniSat wallet:")
    print("   a) Open UniSat wallet extension")
    print("   b) Click 'Import Wallet'")
    print("   c) Choose 'Mnemonic Phrase'")
    print("   d) Enter the mnemonic above")
    print("   e) Your wallet will be imported!\n")
    
    print("✅ Demo completed successfully!")


if __name__ == "__main__":
    asyncio.run(main())