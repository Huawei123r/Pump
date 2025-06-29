# pump_monitor.py (Full Code - Latest Version, ATA Derivation Fix)

import asyncio
import json
import base64
import websockets # Core library for WebSocket connections
import websockets.exceptions 
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from solders.transaction import Transaction, VersionedTransaction
from solders.message import MessageV0
from solders.instruction import Instruction, AccountMeta
from solders.system_program import ID as SYSTEM_PROGRAM_ID
# No more importing TOKEN_PROGRAM_ID (now a constant) or get_associated_token_address (now derived)
# REMOVED: from spl.token.client import get_associated_token_address # Removed problematic import

from dotenv import load_dotenv
import os
import borsh
import httpx 
import google.generativeai as genai
from solana.rpc.api import Client as SolanaRpcClient
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts 

from pathlib import Path

# --- Configuration ---
load_dotenv()

WSS_URL = os.getenv("SOLANA_WSS_URL")
HTTP_URL = os.getenv("SOLANA_HTTP_URL")
PRIVATE_KEY_B58 = os.getenv("SOLANA_PRIVATE_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
BUY_SOL_AMOUNT = float(os.getenv("BUY_SOL_AMOUNT", "0.001")) # Default to 0.001 SOL if not set
BUY_SLIPPAGE_BPS = int(os.getenv("BUY_SLIPPAGE_BPS", "500")) # Default 500 bps (0.5%)

# --- Basic Validation of .env variables ---
if not WSS_URL:
    print("CRITICAL ERROR: SOLANA_WSS_URL not found in .env. Exiting.")
    exit()
if not HTTP_URL:
    print("CRITICAL ERROR: SOLANA_HTTP_URL not found in .env. Exiting.")
    exit()
if not PRIVATE_KEY_B58:
    print("CRITICAL ERROR: SOLANA_PRIVATE_KEY not found in .env. Exiting.")
    exit()
if not GEMINI_API_KEY:
    print("CRITICAL ERROR: GEMINI_API_KEY not found in .env. Exiting.")
    exit()
if BUY_SOL_AMOUNT <= 0:
    print("CRITICAL ERROR: BUY_SOL_AMOUNT must be a positive number. Exiting.")
    exit()
if not (0 <= BUY_SLIPPAGE_BPS <= 10000):
    print("CRITICAL ERROR: BUY_SLIPPAGE_BPS must be between 0 and 10000. Exiting.")
    exit()

# Configure Google Gemini AI
genai.configure(api_key=GEMINI_API_KEY)
# Initialize the generative model
gemini_model = genai.GenerativeModel('gemini-pro')

# Initialize HTTP clients
general_http_client = httpx.AsyncClient() # For non-Solana specific HTTP requests (e.g., fetching URI metadata)
solana_rpc_client = SolanaRpcClient(HTTP_URL) # For Solana RPC calls (e.g., get_latest_blockhash, send_transaction)


try:
    wallet_keypair = Keypair.from_base58_string(PRIVATE_KEY_B58)
    print(f"Wallet Public Key: {wallet_keypair.pubkey()}")
except Exception as e:
    print(f"CRITICAL ERROR: Could not load Solana private key from .env: {e}")
    print("Please ensure SOLANA_PRIVATE_KEY is a valid Base58 encoded private key.")
    exit()


PUMPFUN_PROGRAM_ID = Pubkey.from_string("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P")
PUMPFUN_PROGRAM_ID_STR = str(PUMPFUN_PROGRAM_ID) 

# Define TOKEN_PROGRAM_ID as a constant Pubkey
TOKEN_PROGRAM_ID = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
# Define ASSOCIATED_TOKEN_PROGRAM_ID as a constant Pubkey
ASSOCIATED_TOKEN_PROGRAM_ID = Pubkey.from_string("ATokenGPvbdGVbGfGSFexuHpHx2MVc5MjS4H2x1tXy6")

# --- NEW: Helper function to derive Associated Token Account (ATA) address ---
def derive_associated_token_address(owner: Pubkey, mint: Pubkey) -> Pubkey:
    """
    Derives the Associated Token Account (ATA) address for a given owner and mint.
    """
    return Pubkey.find_program_address(
        [bytes(owner), bytes(TOKEN_PROGRAM_ID), bytes(mint)],
        ASSOCIATED_TOKEN_PROGRAM_ID
    )[0] # [0] because find_program_address returns (pubkey, nonce)


# Pump.fun Instruction Discriminators (from pump-fun.json IDL - SHA256 of instruction name)
BUY_INSTRUCTION_DISCRIMINATOR = bytes([160, 219, 137, 240, 116, 219, 237, 201]) # SHA256 of "global:buy" truncated to 8 bytes

CREATE_INSTRUCTION_DISCRIMINATOR = bytes([24, 30, 200, 40, 5, 28, 7, 119])

def decode_create_instruction_data(data_bytes: bytes):
    if not data_bytes.startswith(CREATE_INSTRUCTION_DISCRIMINATOR):
        raise ValueError("Data does not start with 'create' instruction discriminator.")

    payload_bytes = data_bytes[8:]
    reader = borsh.Borsh(payload_bytes)

    try:
        name_len = reader.read_u32()
        name = reader.read_bytes(name_len).decode('utf-8')

        symbol_len = reader.read_u32()
        symbol = reader.read_bytes(symbol_len).decode('utf-8')

        uri_len = reader.read_u32()
        uri = reader.read_bytes(uri_len).decode('utf-8')

        creator_bytes = reader.read_bytes(32)
        creator = Pubkey.from_bytes(creator_bytes)

        return {
            "name": name,
            "symbol": symbol,
            "uri": uri,
            "creator": creator
        }
    except Exception as e:
        print(f"Error during manual Borsh deserialization: {e}")
        raise

async def get_ai_assessment(token_name, token_symbol, token_uri, new_token_mint):
    """
    Calls Gemini AI to assess the token's legitimacy/potential.
    """
    prompt = (
        f"Analyze this newly created Solana meme token and provide a brief assessment "
        f"of its potential, legitimacy, or any red flags based on the provided information. "
        f"Focus on the name, symbol, and URI content. "
        f"Token Name: '{token_name}', Symbol: '{token_symbol}', Mint Address: '{new_token_mint}'.\n"
        f"URI: '{token_uri}' (You may attempt to fetch and analyze content from this URI if it's a valid URL, "
        f"but do not make external network calls if not possible or if it's not a standard HTTP/S URI).\n"
        f"Provide your assessment as a short, concise paragraph (max 100 words), and then state 'Assessment: [Positive/Neutral/Negative]'."
    )
    
    uri_content = "URI content not fetched or not applicable."
    if token_uri.startswith("http://") or token_uri.startswith("https://"):
        try:
            response = await general_http_client.get(token_uri, timeout=5)
            response.raise_for_status()
            uri_content = response.text[:500]
            prompt += f"\n\nURI Content (first 500 chars): {uri_content}"
        except Exception as e:
            uri_content = f"Failed to fetch URI content: {e}"
            prompt += f"\n\nNote: Failed to fetch URI content for AI analysis: {uri_content}"
    elif token_uri.startswith("ipfs://"):
        prompt += f"\n\nNote: IPFS URI detected. Content not automatically fetched for AI analysis."

    try:
        print(f"Sending token data to Gemini AI for assessment...")
        ai_response = await gemini_model.generate_content_async(prompt)
        assessment_text = ai_response.text
        print(f"AI Assessment Received:\n{assessment_text}")
        return assessment_text
    except Exception as e:
        print(f"Error getting AI assessment: {e}")
        return f"AI assessment failed: {e}"

# --- REAL BUY LOGIC START ---
async def execute_buy_trade(token_mint: Pubkey, sol_amount: float, wallet_keypair: Keypair):
    """
    Executes a buy trade for the specified token on Pump.fun.
    """
    print(f"\n--- Initiating REAL Buy Order for {token_mint} with {sol_amount} SOL ---")
    
    sol_lamports = int(sol_amount * 1_000_000_000)

    # 1. Derive necessary PDAs and ATAs
    bonding_curve_seed = b"bonding-curve"
    (bonding_curve_pubkey, _nonce) = Pubkey.find_program_address(
        [bonding_curve_seed, bytes(token_mint)], PUMPFUN_PROGRAM_ID
    )
    print(f"Bonding Curve PDA: {bonding_curve_pubkey}")

    # Use our custom derivation function
    user_token_account_pubkey = derive_associated_token_address(wallet_keypair.pubkey(), token_mint)
    print(f"User ATA for new token: {user_token_account_pubkey}")

    global_seed = b"global"
    (global_pubkey, _nonce) = Pubkey.find_program_address(
        [global_seed], PUMPFUN_PROGRAM_ID
    )
    print(f"Global Account PDA: {global_pubkey}")

    mint_authority_seed = b"mint-authority"
    (mint_authority_pubkey, _nonce) = Pubkey.find_program_address(
        [mint_authority_seed], PUMPFUN_PROGRAM_ID
    )
    print(f"Mint Authority PDA: {mint_authority_pubkey}")

    # 2. Get latest blockhash for transaction
    try:
        recent_blockhash_resp = await asyncio.to_thread(solana_rpc_client.get_latest_blockhash)
        recent_blockhash = recent_blockhash_resp.value.blockhash
        last_valid_block_height = recent_blockhash_resp.value.last_valid_block_height
        print(f"Latest Blockhash: {recent_blockhash}")
    except Exception as e:
        print(f"ERROR: Could not get latest blockhash: {e}")
        return "BUY_FAILED_BLOCKHASH"

    # 3. Construct the 'buy' instruction data (Borsh serialized)
    buy_instruction_payload = borsh.Borsh.write_u64(sol_lamports) + borsh.Borsh.write_u64(BUY_SLIPPAGE_BPS)
    buy_instruction_data = BUY_INSTRUCTION_DISCRIMINATOR + buy_instruction_payload

    # 4. Construct the instruction (AccountMeta list based on IDL order)
    buy_keys = [
        AccountMeta(pubkey=global_pubkey, is_signer=False, is_writable=True), # 0. global
        AccountMeta(pubkey=bonding_curve_pubkey, is_signer=False, is_writable=True), # 1. bonding_curve
        AccountMeta(pubkey=bonding_curve_pubkey, is_signer=False, is_writable=True), # 2. associated_bonding_curve (often same as bonding_curve for native SOL)
        AccountMeta(pubkey=token_mint, is_signer=False, is_writable=False), # 3. mint
        AccountMeta(pubkey=wallet_keypair.pubkey(), is_signer=True, is_writable=True), # 4. user (signer)
        AccountMeta(pubkey=user_token_account_pubkey, is_signer=False, is_writable=True), # 5. user_token_account
        AccountMeta(pubkey=mint_authority_pubkey, is_signer=False, is_writable=False), # 6. mint_authority
        AccountMeta(pubkey=Pubkey.from_string("SysvarRent111111111111111111111111111111111"), is_signer=False, is_writable=False), # 7. rent (sysvar)
        AccountMeta(pubkey=SYSTEM_PROGRAM_ID, is_signer=False, is_writable=False), # 8. system_program
        AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False), # 9. token_program
        AccountMeta(pubkey=ASSOCIATED_TOKEN_PROGRAM_ID, is_signer=False, is_writable=False), # 10. associated_token_program
    ]

    buy_instruction = Instruction(
        program_id=PUMPFUN_PROGRAM_ID,
        data=buy_instruction_data,
        keys=buy_keys,
    )
    
    # 5. Build and sign the transaction
    try:
        message = MessageV0.try_compile(
            payer=wallet_keypair.pubkey(),
            instructions=[buy_instruction],
            recent_blockhash=recent_blockhash,
        )
        transaction = VersionedTransaction(message, [wallet_keypair]) # Sign with your keypair
        
        # 6. Send the transaction
        opts = TxOpts(
            skip_preflight=False,
            preflight_commitment=Confirmed,
            max_retries=10
        )
        print(f"Sending buy transaction for {token_mint}...")
        
        response = await asyncio.to_thread(solana_rpc_client.send_versioned_transaction, transaction, opts=opts)
        
        tx_signature = response.value
        if tx_signature:
            print(f"Buy transaction sent! Signature: {tx_signature}")
            # 7. Monitor confirmation
            print(f"Waiting for transaction {tx_signature} confirmation...")
            confirmation_response = await asyncio.to_thread(
                solana_rpc_client.confirm_transaction,
                tx_signature,
                commitment=Confirmed,
                last_valid_block_height=last_valid_block_height
            )
            if confirmation_response.value.value:
                if confirmation_response.value.value.err is None:
                    print(f"Transaction {tx_signature} confirmed successfully!")
                    return tx_signature
                else:
                    print(f"Transaction {tx_signature} confirmed with error: {confirmation_response.value.value.err}")
                    return f"BUY_FAILED_CONFIRMATION_WITH_ERROR: {confirmation_response.value.value.err}"
            else:
                print(f"Transaction {tx_signature} failed to confirm (timeout or unknown error).")
                return "BUY_FAILED_CONFIRMATION_TIMEOUT"
        else:
            print("ERROR: Failed to send transaction, no signature received.")
            print(response)
            return "BUY_FAILED_SEND"

    except Exception as e:
        print(f"CRITICAL ERROR during buy transaction: {e}")
        return f"BUY_FAILED_EXCEPTION: {e}"


print(f"Connecting to Solana WebSocket at: {WSS_URL}")
print(f"Monitoring Pump.fun Program ID: {PUMPFUN_PROGRAM_ID}")

async def pump_fun_listener():
    """
    Listens for logs on Solana Mainnet by sending a raw JSON-RPC WebSocket subscribe request.
    Integrates Gemini AI for token analysis and includes a placeholder for buy actions.
    """
    try:
        async with websockets.connect(WSS_URL) as ws:
            subscribe_request = {
                "jsonrpc": "2.0",
                "id": 1, 
                "method": "logsSubscribe",
                "params": [
                    {"mentions": [PUMPFUN_PROGRAM_ID_STR]}, # Filter by Pump.fun program ID as a string
                    {"commitment": "confirmed"}
                ]
            }
            
            await ws.send(json.dumps(subscribe_request))
            print(f"Sent subscription request: {json.dumps(subscribe_request)}")

            # Handle initial response for subscription ID or RPC error
            first_response_raw = await ws.recv() # Get raw string
            print(f"Received first response (raw): {first_response_raw}")

            parsed_first_response = json.loads(first_response_raw)
            if 'result' in parsed_first_response and 'id' in parsed_first_response:
                subscription_id = parsed_first_response['result']
                print(f"Successfully subscribed with ID: {subscription_id}")
            elif 'error' in parsed_first_response:
                print(f"ERROR: RPC returned an error in first response: {parsed_first_response['error']}")
                # Re-raise the error so the outer `try-except` in __main__ catches it
                raise Exception(f"RPC Error during subscription: {parsed_first_response['error']}")
            else:
                print(f"Warning: Unexpected first response structure: {parsed_first_response}")
                raise Exception(f"Unexpected first response: {parsed_first_response}")

            print("Waiting for new token creations (filtering in Python)...")

            async for msg_str in ws:
                try:
                    msg = json.loads(msg_str)
                except json.JSONDecodeError:
                    continue

                if 'params' in msg and 'result' in msg['params'] and 'value' in msg['params']['result']:
                    log_data = msg['params']['result'].get('value', {})
                    signature = log_data.get('signature')
                    logs = log_data.get('logs', [])
                    
                    account_keys_str = log_data.get('accountKeys', [])
                    if PUMPFUN_PROGRAM_ID_STR not in account_keys_str:
                        continue


                    is_new_token_creation = False
                    program_data_log_content = None

                    for i, log_line in enumerate(logs):
                        if "Program log: Instruction: Create" in log_line:
                            is_new_token_creation = True
                            if i + 1 < len(logs) and "Program data: " in logs[i+1]:
                                program_data_log_content = logs[i+1].replace("Program data: ", "")
                            break

                    if is_new_token_creation and program_data_log_content:
                        print(f"\n--- Detected Potential New Pump.fun Token Creation ---")
                        print(f"Transaction Signature: {signature}")
                        print(f"Raw Program Data Log Content: {program_data_log_content[:100]}...")

                        try:
                            decoded_bytes = base64.b64decode(program_data_log_content)
                            decoded_instruction_args = decode_create_instruction_data(decoded_bytes)
                            
                            print(f"Decoded Instruction Data (Args): {decoded_instruction_args}")
                            
                            creator_address_from_args = decoded_instruction_args.get("creator")

                            new_token_mint = None
                            if len(account_keys_str) > 0:
                                new_token_mint = Pubkey.from_string(account_keys_str[0])

                            if new_token_mint and creator_address_from_args:
                                print(f"**Extracted New Token Mint:** {new_token_mint}")
                                print(f"**Extracted Creator Address (from args):** {creator_address_from_args}")
                                token_name = decoded_instruction_args.get("name", "N/A")
                                token_symbol = decoded_instruction_args.get("symbol", "N/A")
                                token_uri = decoded_instruction_args.get("uri", "N/A")
                                print(f"Token Name: {token_name}, Symbol: {token_symbol}, URI: {token_uri}")
                                
                                # --- Call Gemini AI for assessment ---
                                ai_assessment = await get_ai_assessment(
                                    token_name, 
                                    token_symbol, 
                                    token_uri, 
                                    new_token_mint
                                )
                                print(f"\nAI Assessment Complete for {token_symbol}: {ai_assessment.split('Assessment:')[-1].strip()}")

                                # --- Your trading decision logic would go here ---
                                if "Positive" in ai_assessment:
                                    print(f"AI assessment for {token_symbol} is Positive. Initiating buy...")
                                    buy_result = await execute_buy_trade(new_token_mint, BUY_SOL_AMOUNT, wallet_keypair)
                                    print(f"Buy result for {token_symbol}: {buy_result}")
                                else:
                                    print(f"AI assessment for {token_symbol} is not Positive. Skipping buy.")

                            else:
                                print("Warning: Could not reliably extract new token mint or creator address.")
                                print(f"Account Keys received in log: {account_keys_str}")

                            print(f"Proceeding to AI assessment and potential trading decision for {new_token_mint}!")

                        except ValueError as ve:
                            print(f"Error during manual Borsh decoding: {ve}")
                            print(f"Problematic base64 data: {program_data_log_content}")
                        except Exception as e:
                            print(f"An unexpected error occurred during processing for signature {signature}: {e}")
                            print(f"Problematic base64 data: {program_data_log_content}")
    except websockets.exceptions.ConnectionClosedOK as e:
        print(f"ERROR: WebSocket connection closed gracefully (OK): {e}")
        print(f"Code: {e.code}, Reason: {e.reason}")
    except websockets.exceptions.ConnectionClosedError as e:
        print(f"CRITICAL ERROR: WebSocket connection closed abnormally: {e}")
        print(f"Code: {e.code}, Reason: {e.reason}")
    except json.JSONDecodeError as e:
        print(f"CRITICAL ERROR: Could not decode WebSocket message as JSON: {e}")
    except Exception as e:
        print(f"CRITICAL ERROR: An unhandled exception occurred in the pump_fun_listener: {e}")


# Main entry point for the asyncio event loop
if __name__ == "__main__":
    print("Starting Pump.fun monitor...")
    try:
        asyncio.run(pump_fun_listener())
    except KeyboardInterrupt:
        print("\nListener stopped by user (KeyboardInterrupt).")
    except Exception as e:
        print(f"An unexpected error occurred in the main loop: {e}")

