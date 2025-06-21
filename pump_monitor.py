# pump_monitor.py (Full Code - Latest Version, Starting Buy Logic)

import asyncio
import json
import base64
import websockets # Core library for WebSocket connections
import websockets.exceptions 
from solders.pubkey import Pubkey
from solders.keypair import Keypair
# NEW: Import necessary solders types for transactions and instructions
from solders.transaction import Transaction, VersionedTransaction, MessageV0
from solders.instruction import Instruction, AccountMeta
# NEW: Import system program ID
from solders.system_program import ID as SYSTEM_PROGRAM_ID
# NEW: Import token program ID
from solders.token.program import ID as TOKEN_PROGRAM_ID
# NEW: Import get_associated_token_address
from spl.token.client import get_associated_token_address # This is from solana-py's spl library

from dotenv import load_dotenv
import os
import borsh
import httpx # For general HTTP requests (e.g., to fetch token metadata from URI)
import google.generativeai as genai # Import Google Gemini AI library
# NEW: Re-introduce solana.rpc.api.Client for easier HTTP RPC calls
from solana.rpc.api import Client as SolanaRpcClient
from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts # For transaction options

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

# Pump.fun Instruction Discriminators (from pump-fun.json IDL - SHA256 of instruction name)
# This is derived from the IDL (e.g., `_hash_bytes("global:buy")[:8]`)
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
            response = await general_http_client.get(token_uri, timeout=5) # Use the general_http_client
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
    This function requires full implementation of Solana transaction building and sending.
    """
    print(f"\n--- Initiating REAL Buy Order for {token_mint} with {sol_amount} SOL ---")
    
    # Convert SOL amount to lamports (1 SOL = 10^9 lamports)
    sol_lamports = int(sol_amount * 1_000_000_000)

    # 1. Derive necessary PDAs and ATAs
    # Bonding curve account (PDA)
    # Seeds for bonding curve: ["bonding-curve", mint_pubkey]
    bonding_curve_seed = b"bonding-curve"
    (bonding_curve_pubkey, _nonce) = Pubkey.find_program_address(
        [bonding_curve_seed, bytes(token_mint)], PUMPFUN_PROGRAM_ID
    )
    print(f"Bonding Curve PDA: {bonding_curve_pubkey}")

    # Your Associated Token Account (ATA) for the new token
    # This account holds the tokens you receive. It needs to be created if it doesn't exist.
    user_token_account_pubkey = get_associated_token_address(wallet_keypair.pubkey(), token_mint)
    print(f"User ATA for new token: {user_token_account_pubkey}")

    # Pump.fun's global state account (PDA)
    # Seeds for global: ["global"]
    global_seed = b"global"
    (global_pubkey, _nonce) = Pubkey.find_program_address(
        [global_seed], PUMPFUN_PROGRAM_ID
    )
    print(f"Global Account PDA: {global_pubkey}")

    # Pump.fun mint authority (PDA)
    # Seeds for mint authority: ["mint-authority"]
    mint_authority_seed = b"mint-authority"
    (mint_authority_pubkey, _nonce) = Pubkey.find_program_address(
        [mint_authority_seed], PUMPFUN_PROGRAM_ID
    )
    print(f"Mint Authority PDA: {mint_authority_pubkey}")

    # 2. Get latest blockhash for transaction
    try:
        recent_blockhash_resp = await asyncio.to_thread(solana_rpc_client.get_latest_blockhash)
        recent_blockhash = recent_blockhash_resp.value.blockhash
        print(f"Latest Blockhash: {recent_blockhash}")
    except Exception as e:
        print(f"ERROR: Could not get latest blockhash: {e}")
        return "BUY_FAILED_BLOCKHASH"

    # 3. Construct the 'buy' instruction data (Borsh serialized)
    # The 'buy' instruction takes the lamports (SOL amount) as a u64
    # and the slippage basis points as a u64.
    # Instruction data: discriminator (8 bytes) + lamports (8 bytes u64) + slippage (8 bytes u64)
    buy_instruction_payload = borsh.Borsh.write_u64(sol_lamports) + borsh.Borsh.write_u64(BUY_SLIPPAGE_BPS)
    buy_instruction_data = BUY_INSTRUCTION_DISCRIMINATOR + buy_instruction_payload

    # 4. Construct the instruction
    # Based on the pump-fun.json IDL for the 'buy' instruction:
    # accounts:
    # 0. global (writable)
    # 1. bonding_curve (writable)
    # 2. associated_bonding_curve (writable)
    # 3. mint (token_mint)
    # 4. user (wallet_keypair.pubkey(), writable, signer)
    # 5. user_token_account (user_token_account_pubkey, writable) - This is the ATA for the new token
    # 6. mint_authority (PDA)
    # 7. rent (SysvarRent111111111111111111111111111111111)
    # 8. system_program (11111111111111111111111111111111)
    # 9. token_program (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
    # 10. associated_token_program (ATokenGPvbdGV aGRbSFexuHpHx2MVc5MjS4H2x1tXy6) - Not explicitly in buy instruction, but often needed implicitly or for ATA creation

    # Create the buy instruction
    # Note: `get_associated_token_address` is from solana-py, which means `spl.token.client` must be available
    # It seems we removed solana-py, so this might need careful handling or re-introduction of minimal solana-py components.
    # Let's ensure solana-py is in requirements.txt if get_associated_token_address is used.
    
    # Accounts for the buy instruction
    buy_keys = [
        AccountMeta(pubkey=global_pubkey, is_signer=False, is_writable=True),
        AccountMeta(pubkey=bonding_curve_pubkey, is_signer=False, is_writable=True),
        # associated_bonding_curve - This is program derived. Need to get it.
        # Based on IDL, it's just the bonding curve's ATA for SOL.
        # pubkey=get_associated_token_address(bonding_curve_pubkey, Pubkey.from_string("So11111111111111111111111111111111111111112")), # SOL Mint is not a standard token, it's native.
        # This is the System account for the bonding curve, not an ATA.
        AccountMeta(pubkey=bonding_curve_pubkey, is_signer=False, is_writable=True), # This is likely 'associated_bonding_curve' if it's the SOL account
        AccountMeta(pubkey=token_mint, is_signer=False, is_writable=False),
        AccountMeta(pubkey=wallet_keypair.pubkey(), is_signer=True, is_writable=True),
        AccountMeta(pubkey=user_token_account_pubkey, is_signer=False, is_writable=True), # User's ATA for the new token
        AccountMeta(pubkey=mint_authority_pubkey, is_signer=False, is_writable=False),
        AccountMeta(pubkey=Pubkey.from_string("SysvarRent111111111111111111111111111111111"), is_signer=False, is_writable=False),
        AccountMeta(pubkey=SYSTEM_PROGRAM_ID, is_signer=False, is_writable=False),
        AccountMeta(pubkey=TOKEN_PROGRAM_ID, is_signer=False, is_writable=False),
        # Associated Token Program ID needs to be explicitly passed for ATA creation in some contexts.
        # If the ATA doesn't exist, it will be created by the instruction.
        AccountMeta(pubkey=Pubkey.from_string("ATokenGPvbdGVbGfGSFexuHpHx2MVc5MjS4H2x1tXy6"), is_signer=False, is_writable=False), # Associated Token Program
    ]

    buy_instruction = Instruction(
        program_id=PUMPFUN_PROGRAM_ID,
        data=buy_instruction_data,
        keys=buy_keys,
    )
    
    # 5. Build and sign the transaction
    try:
        # Create a VersionedTransaction with a MessageV0
        message = MessageV0.try_compile(
            payer=wallet_keypair.pubkey(),
            instructions=[buy_instruction],
            recent_blockhash=recent_blockhash,
            # address_lookup_table_accounts=[] # If using ALTs
        )
        transaction = VersionedTransaction(message, [wallet_keypair]) # Sign with your keypair
        
        # 6. Send the transaction
        opts = TxOpts(
            skip_preflight=False, # Set to True for speed, False for better debugging
            preflight_commitment=Confirmed,
            max_retries=10 # Retry if fails
        )
        print(f"Sending buy transaction for {token_mint}...")
        response = await asyncio.to_thread(solana_rpc_client.send_versioned_transaction, transaction, opts=opts)
        
        tx_signature = response.value
        if tx_signature:
            print(f"Buy transaction sent! Signature: {tx_signature}")
            # 7. Monitor confirmation (optional but recommended)
            print(f"Waiting for transaction {tx_signature} confirmation...")
            confirmation_response = await asyncio.to_thread(
                solana_rpc_client.confirm_transaction,
                tx_signature,
                commitment=Confirmed,
                last_valid_block_height=recent_blockhash_resp.value.last_valid_block_height
            )
            if confirmation_response.value.value: # value.value indicates success/failure
                print(f"Transaction {tx_signature} confirmed!")
                return tx_signature
            else:
                print(f"Transaction {tx_signature} failed to confirm or errored.")
                print(confirmation_response.value.value)
                return "BUY_FAILED_CONFIRMATION"
        else:
            print("ERROR: Failed to send transaction, no signature received.")
            print(response) # Print full RPC response for debugging
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

            try:
                print(f"Awaiting first response (expecting subscription ID or error from RPC)...")
                first_response_raw = await ws.recv() # Get raw string
                print(f"Received first response (raw): {first_response_raw}")

                parsed_first_response = json.loads(first_response_raw)
                if 'result' in parsed_first_response and 'id' in parsed_first_response:
                    subscription_id = parsed_first_response['result']
                    print(f"Successfully subscribed with ID: {subscription_id}")
                elif 'error' in parsed_first_response:
                    print(f"ERROR: RPC returned an error in first response: {parsed_first_response['error']}")
                    raise Exception(f"RPC Error during subscription: {parsed_first_response['error']}")
                else:
                    print(f"Warning: Unexpected first response structure: {parsed_first_response}")
                    raise Exception(f"Unexpected first response: {parsed_first_response}")

            except websockets.exceptions.ConnectionClosedOK as e:
                print(f"ERROR: WebSocket connection closed gracefully (OK): {e}")
                print(f"Code: {e.code}, Reason: {e.reason}")
                return
            except websockets.exceptions.ConnectionClosedError as e:
                print(f"CRITICAL ERROR: WebSocket connection closed abnormally: {e}")
                print(f"Code: {e.code}, Reason: {e.reason}")
                return
            except json.JSONDecodeError as e:
                print(f"CRITICAL ERROR: Could not decode WebSocket message as JSON: {e}")
                return
            except Exception as e:
                print(f"CRITICAL ERROR: An unexpected error occurred during initial subscription handshake: {e}")
                return


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

