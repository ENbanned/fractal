"""
Fractal Bitcoin Library Usage Examples

This file demonstrates key features of the Fractal Bitcoin library.
"""

import asyncio
import logging
from decimal import Decimal

from fractal import Fractal, Network, connect
from fractal.crypto import PrivateKey
from fractal.modules import FeePriority

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


async def basic_connection_example():
    """Example 1: Basic connection and chain info."""
    print("\n=== Basic Connection Example ===")
    
    # Method 1: Using convenience function
    client = connect()  # Defaults to mainnet HTTP
    
    # Method 2: Creating client with specific provider
    # client = Fractal.create_http_client(network=Network.TESTNET)
    # client = Fractal.create_websocket_client()
    
    async with client:
        # Get chain information
        info = await client.get_chain_info()
        print(f"Network: {info['network']}")
        print(f"Height: {info['height']}")
        print(f"Latest block: {info['latest_block']}")
        print(f"Difficulty: {info['difficulty']}")
        print(f"Mempool size: {info['mempool_size']} vBytes")
        print(f"Price USD: ${info['price_usd']}")


async def address_operations_example():
    """Example 2: Address operations."""
    print("\n=== Address Operations Example ===")
    
    async with connect() as client:
        # Example address (replace with real address)
        address = "bc1p36zfu7jlfcup4wq5pre3t74l248h6ghlv420plf4vy88mnhueu3qs76vev"
        
        # Get address info
        info = await client.address.get_info(address)
        print(f"Address: {info.address}")
        print(f"Balance: {info.balance} sats ({info.balance / 100_000_000:.8f} BTC)")
        print(f"Confirmed: {info.confirmed_balance} sats")
        print(f"Unconfirmed: {info.unconfirmed_balance} sats")
        print(f"Total TXs: {info.tx_count}")
        
        # Get UTXOs
        utxos = await client.address.get_utxos(address, confirmed_only=True)
        print(f"\nUTXOs: {len(utxos)}")
        for utxo in utxos[:3]:  # Show first 3
            print(f"  {utxo.outpoint}: {utxo.value} sats")


async def block_exploration_example():
    """Example 3: Block exploration."""
    print("\n=== Block Exploration Example ===")
    
    async with connect() as client:
        # Get latest block
        latest = await client.block.get_latest()
        print(f"Latest block: {latest.hash}")
        print(f"Height: {latest.height}")
        print(f"Time: {latest.timestamp}")
        print(f"Transactions: {latest.tx_count}")
        print(f"Size: {latest.size} bytes")
        print(f"Difficulty: {latest.difficulty}")
        
        # Get block by height
        block = await client.block.get_block(latest.height - 10)
        print(f"\nBlock at height {block.height}: {block.hash}")
        
        # Get block stats
        stats = await client.block.get_stats(block.height)
        print(f"Average fee: {stats.avg_fee} sats")
        print(f"Total fees: {stats.total_fee} sats")


async def transaction_example():
    """Example 4: Transaction operations."""
    print("\n=== Transaction Example ===")
    
    async with connect() as client:
        # Example transaction (replace with real txid)
        txid = "b41f2fdc343d2d379788b4d42d051dbfaf7908e22fbb961d8bc9ae108932ab12"
        
        try:
            # Get transaction
            tx = await client.tx.get(txid)
            print(f"Transaction: {tx.txid}")
            print(f"Size: {tx.size} bytes, vSize: {tx.vsize} vBytes")
            print(f"Fee: {tx.fee} sats ({tx.fee_rate:.2f} sats/vByte)")
            print(f"Inputs: {len(tx.vin)}, Outputs: {len(tx.vout)}")
            print(f"Confirmed: {tx.is_confirmed}")
            
            # Check output spending status
            for i, output in enumerate(tx.vout[:2]):
                outspend = await client.tx.get_outspend(txid, i)
                spent = outspend.get("spent", False)
                print(f"Output {i}: {output.value} sats - {'SPENT' if spent else 'UNSPENT'}")
                
        except Exception as e:
            print(f"Transaction not found: {e}")


async def fee_estimation_example():
    """Example 5: Fee estimation."""
    print("\n=== Fee Estimation Example ===")
    
    async with connect() as client:
        # Get fee estimates
        estimates = await client.fee.get_estimates()
        print("Fee Estimates (sats/vByte):")
        print(f"  Fastest (next block): {estimates['fastestFee']}")
        print(f"  30 minutes: {estimates['halfHourFee']}")
        print(f"  1 hour: {estimates['hourFee']}")
        print(f"  Economy: {estimates['economyFee']}")
        print(f"  Minimum: {estimates['minimumFee']}")
        
        # Get mempool blocks
        blocks = await client.fee.get_mempool_blocks()
        print(f"\nMempool has {len(blocks)} projected blocks")
        if blocks:
            print(f"Next block: {blocks[0]['nTx']} txs, median fee: {blocks[0]['medianFee']} sats/vB")
        
        # Estimate transaction fee
        vsize = 250  # Typical transaction
        priority = FeePriority.HALF_HOUR
        fee = await client.fee.estimate_transaction_fee(vsize, priority)
        print(f"\nEstimated fee for {vsize} vByte tx: {fee} sats")


async def wallet_example():
    """Example 6: Wallet operations."""
    print("\n=== Wallet Example ===")
    
    async with connect(network=Network.MAINNET) as client:
        # Create wallet
        wallet = client.wallet.create_wallet("my_wallet")
        
        # Create accounts
        account1 = wallet.create_account(label="Primary")
        account2 = wallet.create_account(label="Secondary")
        
        print(f"Wallet: {wallet.name}")
        print(f"Account 1: {account1.address} ({account1.label})")
        print(f"  P2PKH: {account1.p2pkh_address}")
        print(f"  P2WPKH: {account1.p2wpkh_address}")
        print(f"  P2TR: {account1.p2tr_address}")
        
        # Import existing key
        # wif = "KyPi4kWcwCaGJVr4TT27M1kPYVsN5XVswRd7vPvfHaxMVzyq3iBs"
        # imported = wallet.import_wif(wif, label="Imported")
        
        # Check balance (will be 0 for new wallet)
        balance = await wallet.get_balance()
        print(f"\nTotal wallet balance: {balance} sats")
        
        # Export private keys (BE CAREFUL!)
        # keys = wallet.export_private_keys()
        # print(f"Exported {len(keys)} private keys")


async def key_management_example():
    """Example 7: Key and crypto operations."""
    print("\n=== Key Management Example ===")
    
    # Create new private key
    private_key = PrivateKey.create()
    print(f"Private key: {private_key.hex()[:8]}...{private_key.hex()[-8:]}")
    
    # Get public key
    public_key = private_key.public_key(compressed=True)
    print(f"Public key: {public_key.hex()}")
    
    # Generate addresses
    p2pkh = public_key.p2pkh_address(Network.MAINNET)
    p2wpkh = public_key.p2wpkh_address(Network.MAINNET)
    p2tr = public_key.p2tr_address(Network.MAINNET)
    
    print(f"P2PKH address: {p2pkh}")
    print(f"P2WPKH address: {p2wpkh}")
    print(f"P2TR address: {p2tr}")
    
    # Export/Import WIF
    wif = private_key.wif(Network.MAINNET)
    print(f"\nWIF: {wif}")
    
    # Import from WIF
    imported_key, compressed, network = PrivateKey.from_wif(wif)
    print(f"Imported: compressed={compressed}, network={network.value}")
    
    # Sign message
    from fractal.crypto import sign_message, verify_message
    message = "Hello Fractal Bitcoin!"
    signature = sign_message(private_key, message)
    print(f"\nMessage signature: {signature.hex()[:16]}...")


async def mining_stats_example():
    """Example 8: Mining statistics."""
    print("\n=== Mining Statistics Example ===")
    
    async with connect() as client:
        # Get difficulty adjustment
        diff_adj = await client.mining.get_difficulty_adjustment()
        print(f"Progress: {diff_adj['progressPercent']:.2f}%")
        print(f"Difficulty change: {diff_adj['difficultyChange']:.2f}%")
        print(f"Blocks remaining: {diff_adj['remainingBlocks']}")
        
        # Get hashrate
        hashrate = await client.mining.get_hashrate()
        current_hr = hashrate['currentHashrate'] / 1e18  # Convert to EH/s
        print(f"\nNetwork hashrate: {current_hr:.2f} EH/s")
        
        # Get top mining pools
        pools = await client.mining.get_mining_pools("1w")
        print(f"\nTop mining pools (past week):")
        for pool in pools['pools'][:5]:
            print(f"  {pool.name}: {pool.blockCount} blocks ({pool.blockCount/pools['blockCount']*100:.1f}%)")


async def price_data_example():
    """Example 9: Price data."""
    print("\n=== Price Data Example ===")
    
    async with connect() as client:
        # Get current prices
        prices = await client.price.get_current()
        print("Current Bitcoin prices:")
        for currency in ["USD", "EUR", "GBP", "JPY"]:
            if currency in prices:
                print(f"  {currency}: {prices[currency]:,}")
        
        # Get price change
        change = await client.price.get_price_change(hours=24, currency="USD")
        print(f"\n24h price change:")
        print(f"  Current: ${change['current_price']:,.2f}")
        print(f"  Change: {change['change_percent']:+.2f}%")
        
        # Convert currency
        btc_amount = 0.1
        usd_value = await client.price.convert_currency(btc_amount, "BTC", "USD")
        print(f"\n{btc_amount} BTC = ${usd_value:,.2f}")


async def websocket_example():
    """Example 10: WebSocket real-time updates."""
    print("\n=== WebSocket Example ===")
    
    # Create WebSocket client
    client = Fractal.create_websocket_client()
    
    # Define callback for new blocks
    def on_block(data):
        print(f"New block: {data}")
    
    # Define callback for mempool updates
    def on_mempool(data):
        print(f"Mempool update: {data}")
    
    async with client:
        # Subscribe to new blocks
        await client.block.subscribe_to_blocks(callback=on_block)
        
        # Subscribe to mempool
        await client.mempool.subscribe_to_mempool(callback=on_mempool)
        
        print("Listening for updates... (press Ctrl+C to stop)")
        
        # Keep listening for 30 seconds
        await asyncio.sleep(30)
        
        # Unsubscribe
        await client.block.unsubscribe_from_blocks()
        await client.mempool.unsubscribe_from_mempool()


async def main():
    """Run all examples."""
    examples = [
        basic_connection_example,
        address_operations_example,
        block_exploration_example,
        transaction_example,
        fee_estimation_example,
        wallet_example,
        key_management_example,
        mining_stats_example,
        price_data_example,
        # websocket_example,  # Uncomment to test WebSocket
    ]
    
    for example in examples:
        try:
            await example()
        except Exception as e:
            print(f"Error in {example.__name__}: {e}")
        
        # Small delay between examples
        await asyncio.sleep(1)


if __name__ == "__main__":
    # Run examples
    asyncio.run(main())