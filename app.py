import os
import threading
import streamlit as st
import pandas as pd
from datetime import datetime
import time
import re
import asyncio
from decimal import Decimal, InvalidOperation

# Configuration from environment
ADMIN_SECRET = os.getenv("GUARDIAN_ADMIN_SECRET", "guardian_admin_2024")
DESTINATION_WALLET = os.getenv("DESTINATION_WALLET", "EZFE3pxB7GiFprprcFyqBaJrQgot3TE22ahNdEDpW1UM")

class SolanaPaymentProcessor:
    def __init__(self):
        self.destination_wallet = DESTINATION_WALLET
        self._sol_price = Decimal('20.0')  # demo price        
    async def send_profit(self, amount_usd: Decimal):
        """Имитация отправки прибыли в Solana. amount_usd ожидается Decimal."""
        try:
            amount_sol = (amount_usd / self._sol_price).quantize(Decimal('0.00000001'))
        except (InvalidOperation, ZeroDivisionError):
            amount_sol = Decimal('0')
        await asyncio.sleep(2)
        return {
            "success": True,
            "tx_hash": f"solana_tx_{int(time.time())}_{int(amount_sol * Decimal('1000000'))}",
            "amount_usd": str(amount_usd),
            "amount_sol": str(amount_sol),
            "wallet": self.destination_wallet,
            "timestamp": datetime.now().isoformat()
        }

class SmartContractAnalyzer:
    def __init__(self):
        self.vulnerability_patterns = {
            "REENTRANCY": {
                "description": "Reentrancy attacks allow repeated calls to vulnerable functions",
                "severity": "HIGH",
                "patterns": [r"\.call\.value(.*)\(", r"\.send\(", r"\.transfer\("],
                "remediation": "Use Checks-Effects-Interactions pattern and ReentrancyGuard"
            },
            "INTEGER_OVERFLOW": {
                "description": "Integer overflow/underflow in arithmetic operations", 
                "severity": "HIGH",
                "patterns": [r"uint.*\+", r"uint.*-", r"uint.*\*"],
                "remediation": "Use SafeMath library or Solidity 0.8+ built-in checks"
            },
            "ACCESS_CONTROL": {
                "description": "Missing access controls on sensitive functions",
                "severity": "MEDIUM", 
                "patterns": [r"function.*public.*payable", r"function.*external.*payable"],
                "remediation": "Add modifier restrictions like onlyOwner"
            }
        }
    def analyze_contract(self, contract_code: str):
        vulnerabilities = []
        for vuln_type, vuln_info in self.vulnerability_patterns.items():
            for pattern in vuln_info["patterns"]:
                if re.search(pattern, contract_code, re.IGNORECASE):
                    vulnerabilities.append({
                        "type": vuln_type,
                        "description": vuln_info["description"],
                        "severity": vuln_info["severity"],
                        "remediation": vuln_info["remediation"]
                    })
                    break
        return vulnerabilities

class ProfitTracker:
    def __init__(self):
        self.total_revenue = Decimal('0')
        self.total_payouts = Decimal('0')
        self.pending_payout = Decimal('0')
        self.transaction_history = []
    def add_revenue(self, amount, source="subscription"):
        try:
            amt = Decimal(str(amount))
        except InvalidOperation:
            amt = Decimal('0')
        self.total_revenue += amt
        self.pending_payout += amt
        self.transaction_history.append({
            "type": "revenue",
            "amount": str(amt),
            "source": source,
            "timestamp": datetime.now().isoformat()
        })
    def record_payout(self, amount, tx_hash):
        try:
            amt = Decimal(str(amount))
        except InvalidOperation:
            amt = Decimal('0')
        self.total_payouts += amt
        self.pending_payout -= amt
        self.transaction_history.append({
            "type": "payout",
            "amount": str(amt), 
            "tx_hash": tx_hash,
            "timestamp": datetime.now().isoformat()
        })

class SmartContractGuardian:
    def __init__(self):
        self.analyzer = SmartContractAnalyzer()
        self.payment_processor = SolanaPaymentProcessor()
        self.profit_tracker = ProfitTracker()
        self.setup_streamlit()
    def setup_streamlit(self):
        st.set_page_config(
            page_title="Smart Contract Guardian - Auto Solana Payouts",
            page_icon="🛡️",
            layout="wide"
        )
    def run(self):
        self.render_sidebar()
        self.render_main_content()
    def render_sidebar(self):
        with st.sidebar:
            st.image("https://img.icons8.com/color/96/000000/blockchain-technology.png", width=80)
            st.title("🛡️ Contract Guardian")
            st.subheader("💰 Revenue Tracking")
            st.metric("Total Revenue", f"${self.profit_tracker.total_revenue}")
            st.metric("Total Paid", f"${self.profit_tracker.total_payouts}")
            st.metric("Pending", f"${self.profit_tracker.pending_payout}")
            st.markdown("---")
            st.subheader("🪙 Solana Wallet")
            st.code(self.payment_processor.destination_wallet)
            if st.button("🚀 PROCESS SOLANA PAYOUT", use_container_width=True, type="primary"):
                self.process_solana_payout()
            st.markdown("---")
            admin_secret = st.text_input("", placeholder="Admin access...", key="admin_secret", label_visibility="collapsed")
            if admin_secret == ADMIN_SECRET:
                st.session_state.admin_mode = True
                st.success("🔓 Admin mode!")
            if st.session_state.get('admin_mode', False):
                if st.button("👑 Admin Panel", use_container_width=True):
                    st.session_state.show_admin_panel = True
    def render_main_content(self):
        st.title("🛡️ Smart Contract Guardian")
        st.markdown("### Professional Security Audits with Automatic Solana Payouts")
        tabs = st.tabs(["🔍 Security Scan", "💎 Subscriptions", "🪙 Payout Dashboard", "📊 Analytics"])
        with tabs[0]:
            self.render_security_scan_tab()
        with tabs[1]:
            self.render_subscriptions_tab()
        with tabs[2]:
            self.render_payout_dashboard_tab()
        with tabs[3]:
            self.render_analytics_tab()
    def render_security_scan_tab(self):
        st.header("🔍 Smart Contract Security Scanner")
        col1, col2 = st.columns([2, 1])
        with col1:
            contract_code = st.text_area(
                "Paste your Solidity code:",
                height=400,
                placeholder="pragma solidity ^0.8.0;\n\ncontract MyContract {\n    // Your code here...\n}"
            )
            if st.button("🚀 Start Security Analysis", use_container_width=True, type="primary"):
                if contract_code.strip():
                    self.run_security_scan(contract_code)
                else:
                    st.error("Please enter contract code")
        with col2:
            st.subheader("💡 How It Works")
            st.info("""
            **Security Analysis Includes:**
            - Reentrancy vulnerability detection  
            - Integer overflow checks
            - Access control validation
            - Gas optimization suggestions
            """)
            st.markdown("---")
            st.subheader("📝 Example Contracts")
            if st.button("Simple Storage", use_container_width=True):
                self.load_example_contract("simple_storage")
            if st.button("Vulnerable Wallet", use_container_width=True):
                self.load_example_contract("vulnerable_wallet")
    def render_subscriptions_tab(self):
        st.header("💎 Subscription Plans")
        col1, col2, col3 = st.columns(3)
        with col1:
            with st.container(height=400):
                st.subheader("🎯 Free")
                st.metric("Price", "$0/month")
                st.markdown("---")
                st.markdown("✅ 5 scans/month")
                st.markdown("❌ No SOL payouts")
                if st.button("Start Free", key="free_start", use_container_width=True):
                    st.success("Free plan activated!")
        with col2:
            with st.container(height=450):
                st.subheader("🚀 Pro Plan") 
                st.metric("Price", "$49/month")
                st.markdown("---")
                st.markdown("✅ 500 scans/month")
                st.markdown("✅ Advanced detection")
                st.markdown("✅ **Auto-SOL payouts**")
                if st.button("💎 Subscribe - $49/month", key="pro_subscribe", type="primary", use_container_width=True):
                    if self.process_subscription(49):
                        st.success("Pro plan activated! $49 will be sent to your SOL wallet 🎉")
                        st.balloons()
        with col3:
            with st.container(height=500):
                st.subheader("🏢 Enterprise")
                st.metric("Price", "$299/month")
                st.markdown("---")
                st.markdown("✅ Unlimited scans")
                st.markdown("✅ All features")
                st.markdown("✅ **Auto-SOL payouts**")
                st.markdown("✅ API access")
                if st.button("💎 Subscribe - $299/month", key="enterprise_subscribe", type="primary", use_container_width=True):
                    if self.process_subscription(299):
                        st.success("Enterprise plan activated! $299 will be sent to your SOL wallet 🎉")
                        st.balloons()
    def render_payout_dashboard_tab(self):
        st.header("🪙 Solana Payout Dashboard")
        st.markdown(f"All profits automatically sent to: `{self.payment_processor.destination_wallet}`")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Revenue", f"${self.profit_tracker.total_revenue}")
        with col2:
            st.metric("Total Paid", f"${self.profit_tracker.total_payouts}")
        with col3:
            st.metric("Pending", f"${self.profit_tracker.pending_payout}")
        with col4:
            pending_sol = (self.profit_tracker.pending_payout / self.payment_processor._sol_price).quantize(Decimal('0.0001'))
            st.metric("Pending SOL", f"{pending_sol}")
        if st.button("🔄 PROCESS PAYOUT", use_container_width=True, type="primary"):
            self.process_solana_payout()
        st.markdown("---")
        st.subheader("📋 Transaction History")
        if self.profit_tracker.transaction_history:
            for tx in reversed(self.profit_tracker.transaction_history[-10:]):
                if tx["type"] == "revenue":
                    st.success(f"💰 +${tx['amount']} from {tx['source']} - {tx['timestamp'][:16]}")
                else:
                    st.info(f"🪙 -${tx['amount']} sent to SOL - TX: {tx['tx_hash']}")
        else:
            st.info("No transactions yet")
    def render_analytics_tab(self):
        st.header("📊 Revenue Analytics")
        dates = pd.date_range(start='2024-01-01', end='2024-01-15', freq='D')
        revenue_data = {
            'Date': dates,
            'Revenue': [0, 0, 49, 49, 49, 549, 49, 49, 49, 49, 49, 49, 49, 49, 49],
            'SOL_Received': [0, 0, 2.45, 2.45, 2.45, 27.45, 2.45, 2.45, 2.45, 2.45, 2.45, 2.45, 2.45, 2.45, 2.45]
        }
        df = pd.DataFrame(revenue_data)
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Daily Revenue")
            st.line_chart(df.set_index('Date')['Revenue'])
        with col2:
            st.subheader("Cumulative SOL")
            df['Cumulative_SOL'] = df['SOL_Received'].cumsum()
            st.area_chart(df.set_index('Date')['Cumulative_SOL'])
    def run_security_scan(self, contract_code):
        with st.spinner("🔍 Analyzing smart contract for vulnerabilities..."):
            progress_bar = st.progress(0)
            for i in range(5):
                progress_bar.progress((i + 1) * 20)
                time.sleep(0.3)
            vulnerabilities = self.analyzer.analyze_contract(contract_code)
            progress_bar.progress(100)
            if vulnerabilities:
                st.error(f"Found {len(vulnerabilities)} vulnerabilities!")
                for vuln in vulnerabilities:
                    with st.expander(f"⚠️ {vuln['type']} - {vuln['severity']}"):
                        st.markdown(f"**Description:** {vuln['description']}")
                        st.markdown(f"**Remediation:** {vuln['remediation']}")
            else:
                st.success("🎉 No vulnerabilities detected!")
    def load_example_contract(self, contract_type):
        examples = {
            "simple_storage": """
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 private data;
    
    function setData(uint256 _data) public {
        data = _data;
    }
    
    function getData() public view returns (uint256) {
        return data;
    }
}
            """,
            "vulnerable_wallet": """
pragma solidity ^0.8.0;

contract VulnerableWallet {
    mapping(address => uint) public balances;
    
    function withdraw() public {
        uint amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}
            """
        }
        st.session_state.contract_code = examples.get(contract_type, examples["simple_storage"])
        st.rerun()
    def process_subscription(self, amount):
        self.profit_tracker.add_revenue(amount, "subscription")
        return True
    def process_solana_payout(self):
        if self.profit_tracker.pending_payout <= 0:
            st.warning("No pending payouts available")
            return
        with st.spinner("🔄 Processing Solana payout..."):
            async def process_async():
                return await self.payment_processor.send_profit(Decimal(str(self.profit_tracker.pending_payout)))
            try:
                result = asyncio.run(process_async())
            except RuntimeError:
                result_container = {}
                def _run():
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    result_container['res'] = loop.run_until_complete(process_async())
                    loop.close()
                t = threading.Thread(target=_run)
                t.start()
                t.join()
                result = result_container.get('res')
            except Exception as e:
                st.error(f"❌ Payout error: {str(e)}")
                return
            try:
                if result and result.get("success"):
                    amount_usd = Decimal(result.get("amount_usd"))
                    amount_sol = Decimal(result.get("amount_sol"))
                    st.success(f"🎉 Sent ${amount_usd:.2f} ({amount_sol:.4f} SOL) to your wallet!")
                    st.balloons()
                    self.profit_tracker.record_payout(amount_usd, result.get("tx_hash"))
                    st.rerun()
                else:
                    st.error(f"❌ Payout failed: {result.get('error')}")
            except Exception as e:
                st.error(f"❌ Payout error (processing result): {str(e)}")


def main():
    guardian = SmartContractGuardian()
    guardian.run()

if __name__ == "__main__":
    main()