# **Comprehensive Unified Payments Interface (UPI) FAQ Dataset**

## **1\
## ---

**2\. Registration, VPA Management, and Core Capabilities**

**Q: How is UPI different from traditional Mobile Banking?** **A:** Traditional mobile banking requires you to download the specific application for each bank where you hold an account. UPI provides high-level interoperability, meaning you can download a single UPI application from any participating bank or Third-Party App Provider (TPAP) and link multiple accounts from different banks all within that one app.4

**Q: What are the prerequisites to register for UPI?** **A:** To successfully register, you need an Android or iOS smartphone with an active internet connection, an operative bank account, a mobile number that is officially linked to that bank account for SMS alerts, and an active debit card linked to the account (necessary for generating your initial UPI PIN).4

**Q: Is there a cooling period or restriction when I first register or reset my UPI PIN?**

**A:** Yes. To prevent fraud, the NPCI enforces a security cooling period. For the first 24 hours after registering a new UPI ID or resetting your UPI PIN on an Android device, your transactions are capped at a maximum of ₹5,000. For iOS users, this ₹5,000 daily limit applies for the first 5 days.

**Q: What is a Virtual Payment Address (VPA) and how many can I have?** **A:** A VPA is a unique payment identifier (formatting similar to an email address, e.g., name@bank) that securely masks your actual bank account number and IFSC code. You can create up to 10 distinct VPAs for a single given bank account, or you can link multiple different bank accounts to one single VPA (where one acts as the primary default account).4

**Q: What happens if I delete my VPA? Can I recreate it later?** **A:** No. As a strict security measure per NPCI guidelines, once a Virtual Payment Address is deleted, you are completely blocked from recreating that exact same VPA for the next 2 years.4

**Q: What are the different channels I can use to transfer funds via UPI?** **A:** UPI is highly versatile. You can transfer money using a Virtual Payment Address (VPA), an Account Number combined with an IFSC code, a Mobile Number combined with an MMID, or by using the beneficiary's Aadhaar Number (provided their Aadhaar is linked to their bank account).4

**Q: Can I stop or cancel a UPI payment once I have entered my PIN and initiated it?** **A:** No. Because UPI operates on the Immediate Payment Service (IMPS) channel ensuring instant, real-time credit, a payment cannot be stopped or cancelled once it has been successfully initiated.4

**Q: What should I do if I change my smartphone handset or my SIM card?** **A:** If you change your **handset** but keep the same SIM card, you must download your app again and re-verify your mobile number; you can continue using your existing VPA.4 However, if you change your **SIM card** (even if you retain the same mobile number via porting or updating the bank), you must completely re-register and add your bank accounts afresh. Any previous VPAs associated with the old device binding cannot be used for 2 years.4

**Q: Can I use more than one UPI application on the same mobile phone?** **A:** Yes, you can install and use multiple UPI applications on the same mobile device and link your registered bank accounts to all of them.4

## ---

**3\. Core UPI Mechanics and Transaction Limits**

**Q: What is the maximum amount of money I can transfer via UPI in a single day?**

**A:** The standard daily limit established by the National Payments Corporation of India (NPCI) is ₹1,00,000 for standard Person-to-Person (P2P) and generic Person-to-Merchant (P2M) transactions.

**Q: Are there different transaction limits for specific types of payments?**

**A:** Yes, the NPCI allows enhanced limits for critical categories. You can transfer up to ₹2,00,000 per transaction for capital markets, insurance premiums, collections, and foreign inward remittances. The limit is further increased to ₹5,00,000 per transaction for Initial Public Offerings (IPOs), the RBI Retail Direct Scheme, tax payments, hospitals, and educational institutions.

**Q: Is there a limit on how many UPI transactions I can make in a day?**

**A:** Yes, users are capped at a maximum of 20 standard UPI transactions within a rolling 24-hour window.

**Q: Have there been any recent API restrictions or new rules implemented for UPI applications?** **A:** Yes. To reduce server strain and improve efficiency, new guidelines (effective August 2025\) introduced several limits: users are restricted to 50 balance checks per day, and applications can only fetch/view linked bank accounts 25 times a day.5 There is also a mandatory 90-second cooldown period before a user can check the status of a pending transaction, with a maximum of 3 status checks allowed within a two-hour window.

## ---

**4\. Micro-Transactions and Offline Payments**

**Q: What is UPI Lite, and how is it different from standard UPI?**

**A:** UPI Lite is an on-device digital wallet designed for small, high-frequency transactions. Unlike standard UPI, which requires a PIN for every transfer and routes through your bank's core servers, UPI Lite allows PIN-free transactions. This results in faster payments and a cleaner bank statement, as only wallet top-ups and unloads are recorded in your primary passbook.

**Q: What are the transaction limits for UPI Lite?** **A:** You can make single PIN-free payments up to ₹1,000. You can load a maximum balance of ₹5,000 into the wallet at any given time, and your cumulative daily spending limit using UPI Lite is capped at ₹10,000.7

**Q: What is UPI Lite X, and how does it differ from standard UPI Lite?** **A:** While standard UPI Lite requires an active internet connection, UPI Lite X is designed for completely offline transactions. It uses Near Field Communication (NFC) technology to allow users to tap and pay without cellular data. The offline per-transaction limit for UPI Lite X is ₹500, with a maximum allocated sub-wallet balance of ₹2,000.7

## ---

**5\. Accessibility: Feature Phones and Shared Accounts**

**Q: Can I use UPI if I don't have a smartphone or internet connection?** **A:** Yes. The NPCI offers **UPI 123Pay** specifically for feature phones and offline users. After dialing \*99\# to link your bank account and set a PIN, you can execute payments using four methods: calling an Interactive Voice Response (IVR) number, giving a missed call to a merchant token, using a feature-phone embedded app, or utilizing sound-based proximity technology.9 Transactions are capped at ₹10,000 each.10

**Q: What are the official IVR numbers for UPI 123Pay?** **A:** Users can initiate secure transactions by calling the predefined IVR numbers: 080-4516-3666, 080-4516-3581, or 6366-200-200.9

**Q: How does UPI Circle work for sharing bank accounts with family members?** **A:** UPI Circle allows a "Primary User" to delegate payment capabilities to up to five "Secondary Users" (like dependents or elderly parents) using a single bank account.12 It offers two modes:

1. **Full Delegation:** The primary user sets a rigid monthly spending limit (up to ₹15,000). The secondary user can spend within this limit independently without needing the primary user's PIN.12  
2. **Partial Delegation:** The secondary user initiates the payment, but the primary user receives a prompt on their device and must enter their UPI PIN to approve every single transaction.12

## ---

**6\. Advanced Features: Credit Cards, Credit Lines, and ATMs**

**Q: Can I link my credit card to my UPI app?**

**A:** Yes, but currently this feature is exclusively available for RuPay credit cards. Once linked via your preferred TPAP (like Google Pay or PhonePe), you can scan merchant QR codes and pay using your credit card balance.

**Q: Can I send money to my friends using my linked RuPay credit card?** **A:** No. RuPay credit cards linked to UPI can only be used for Person-to-Merchant (P2M) transactions. Person-to-Person (P2P) transfers to friends or family are strictly prohibited.14

**Q: Are there any extra fees if I pay a merchant using my RuPay credit card via UPI?** **A:** As a customer, you do not pay any extra convenience fees or surcharges.16 However, merchants may be subject to a Merchant Discount Rate (MDR). If a business makes less than ₹20 lakh a year, they pay zero MDR for payments of ₹2,000 or less. For businesses with a turnover exceeding ₹20 lakh, or for transactions above ₹2,000, an MDR ranging from 1.1% to 1.9% is applied.30

**Q: What is a UPI Credit Line and how do I activate it?**

**A:** A UPI Credit Line is a pre-approved, small-ticket credit facility provided by your bank. To activate it, your mobile number must be linked to both Aadhaar and your bank account. You must consent to Aadhaar-based verification via OTP before setting a UPI PIN for the credit line. Once active, you can select the "Credit Line" option during checkout to utilise bank-provided credit.

**Q: How do I withdraw cash from an ATM using UPI?** **A:** Visit an Interoperable Cardless Cash Withdrawal (ICCW) enabled ATM and select "UPI Cash Withdrawal." The ATM will display a dynamic QR code. Scan this code with your UPI app, enter the desired amount (up to the ₹10,000 per transaction limit), authenticate with your UPI PIN, and the ATM will dispense the cash instantly.17

**Q: How do I manage recurring payments or subscriptions on UPI?** **A:** The **UPI AutoPay** feature manages recurring mandates (like Netflix, SIPs, or electricity bills). You have absolute control over these mandates; you can pause, modify the maximum deduction limit, or cancel the subscription permanently directly within your UPI app using your PIN.19

## ---

**7\. International Transactions and NRI Usage**

**Q: Can I use my Indian UPI app while traveling abroad?** **A:** Yes, UPI is expanding globally. Indian travelers can currently scan local merchant QR codes in fully operational corridors like the UAE, France (e.g., Eiffel Tower, Galeries Lafayette), Nepal, Bhutan, Sri Lanka, and Mauritius.31 You must enable "International Payments" within your app and set an active window before scanning. The app will show you the exact equivalent in Indian Rupees (INR) alongside the foreign currency before you enter your PIN.21

**Q: I am a Non-Resident Indian (NRI). Can I use a foreign mobile number to set up UPI?**

**A:** Yes. Under new RBI and NPCI guidelines, NRIs residing in over 12 approved countries (including the US, UK, UAE, and Singapore) can register for UPI using their international mobile numbers.

**Q: Can I link my foreign bank account (e.g., a US or UK bank) to my NRI UPI ID?**

**A:** No. Direct linking of overseas bank accounts to Indian UPI applications remains strictly prohibited under FEMA regulations. Your international mobile number must be officially linked to an active Non-Resident External (NRE) or Non-Resident Ordinary (NRO) account at an Indian bank that supports this feature.

## ---

**8\. Diagnostic Intelligence: Error Codes and Troubleshooting**

**Q: Why did my UPI transaction fail with the error code "U16"?** **A:** The "U16" error means "Risk Threshold Exceeded." You have triggered an automated security block because you breached a limit. This could mean you exceeded the ₹1,00,000 daily value limit, surpassed the 20-transaction volume limit, or attempted to spend more than ₹5,000 within the first 24 hours of registering a new UPI ID.22 You must wait for the 24-hour cooldown period to expire before transacting again.23

**Q: What does the error code "04" mean?** **A:** Error "04" translates to "Insufficient Balance." Your linked bank account does not have adequate funds to complete the requested transfer.32

**Q: What do error codes "ZM" or "Z6" signify?** **A:** These codes represent "Invalid MPIN / PIN Tries Exceeded." You have either entered an incorrect UPI PIN or have exhausted the maximum allowable number of failed cryptographic authentication attempts. You must reset your PIN using your debit card details.33

**Q: What do error codes "XY" or "Y1" mean?** **A:** These represent technical timeouts. "XY" indicates that the Remitter's (Sender's) Core Banking System is offline, while "Y1" means the Beneficiary's (Receiver's) bank is offline.33 You should wait 1 to 2 hours for server stability to be restored before retrying.

**Q: Why am I seeing error code "M3" or "YF"?** **A:** These codes relate to blocked accounts. "M3" means the sender's account has been blocked or frozen by their issuing bank, while "YF" indicates that the beneficiary's (receiver's) account has been blocked or frozen.33 You must contact your bank directly to resolve this compliance issue.

**Q: What does error "91" mean?** **A:** Error "91" is a System Timeout. The transaction request took too long to traverse the network. Check your transaction history before retrying to ensure you are not double-charged.32

**Q: My transaction status says "Pending," and money was deducted from my account. What should I do?** **A:** Do not panic, and do not retry the payment immediately to avoid being double-charged. Pending statuses occur due to asynchronous server delays. The NPCI mandates that pending transactions will automatically reach a final terminal state (either successful credit to the receiver or a refund to your account) within T+2 (Transaction Date \+ 2\) working days.24

**Q: How do I raise an official dispute for a failed transaction or suspected fraud?** **A:** The NPCI operates a strict, tiered Unified Dispute and Issue Resolution (UDIR) framework 25:

1. **Level 1:** File a ticket directly within your Third-Party App (e.g., Google Pay, PhonePe) via the transaction history page.26  
2. **Level 2:** If unresolved by the bank within the turnaround time, escalate the complaint on the official NPCI website under the "UPI Dispute Redressal Mechanism" portal. Raising a dispute via the NPCI is completely free of charge.35  
3. **Level 3:** If still unsatisfied, file a legal grievance with the RBI Integrated Ombudsman.27

## ---

**9\. Threat Vectors and Fraud Mitigation**

**Q: I received a "Request Money" notification from an unknown buyer on a marketplace. Should I enter my PIN to receive the funds?** **A:** **NO.** This is the most common UPI scam. You are *only* ever required to enter your secret UPI PIN to send money to someone else or to authorize a debit from your account.28 You will never need a PIN to receive money.

**Q: A customer support agent asked me to download a screen-sharing app to fix my failed transaction. Is this safe?** **A:** No. Fraudsters posing as bank support utilize remote desktop applications (like AnyDesk or QuickSupport) to hijack your screen, capture your OTPs, and monitor your keystrokes when you type your PIN. Authentic bank representatives will never ask you to download third-party remote software.29

#### **Works cited**

1. Knowledge base, best practices : r/OpenWebUI \- Reddit, accessed March 12, 2026, [https://www.reddit.com/r/OpenWebUI/comments/1ime3hw/knowledge\_base\_best\_practices/](https://urlfiltering.paloaltonetworks.com/test-malware)  
2. RAG Tutorial \- Open WebUI, accessed March 12, 2026, [https://docs.openwebui.com/tutorials/tips/rag-tutorial/](https://urlfiltering.paloaltonetworks.com/test-malware)  
3. How should documents be prepared for use in OpenWebUI Collections (e.g. ERP manuals)? \- Reddit, accessed March 12, 2026, [https://www.reddit.com/r/OpenWebUI/comments/1ljbjov/how\_should\_documents\_be\_prepared\_for\_use\_in/](https://urlfiltering.paloaltonetworks.com/test-malware)  
4. FAQ-on-UPI.pdf  
5. New NPCI UPI Rules to Enhance Security and Efficiency Starting August 1, 2025, ETBFSI, accessed March 12, 2026, [https://bfsi.economictimes.indiatimes.com/articles/new-npci-upi-rules-to-enhance-security-and-efficiency-starting-august-1-2025/122976660](https://urlfiltering.paloaltonetworks.com/test-malware)  
6. India's NPCI announces new UPI rules from August 1: Balance check limits, auto-pay timings revised, fraud prevention strengthened, accessed March 12, 2026, [https://timesofindia.indiatimes.com/etimes/trending/indias-npci-announces-new-upi-rules-from-august-1-balance-check-limits-auto-pay-timings-revised-fraud-prevention-strengthened/articleshow/123043071.cms](https://urlfiltering.paloaltonetworks.com/test-malware)  
7. UPI Lite, UPI Lite X & Regular UPI: Limits, Setup & Guide, accessed March 12, 2026, [https://www.ujjivansfb.bank.in/banking-blogs/banking-services/upi-lite-litex-vs-regular-upi-guide](https://urlfiltering.paloaltonetworks.com/test-malware)  
8. Pay with UPI Lite on Google Pay, accessed March 12, 2026, [https://support.google.com/pay/india/answer/13327133?hl=en](https://urlfiltering.paloaltonetworks.com/test-malware)  
9. UPI 123PAY: UPI Payments for Feature Phones \- Razorpay, accessed March 12, 2026, [https://razorpay.com/blog/what-is-upi-123-pay/](https://urlfiltering.paloaltonetworks.com/test-malware)  
10. UPI 123Pay: Unlocking Digital Payments for Feature Phones \- M2P Fintech, accessed March 12, 2026, [https://m2pfintech.com/blog/upi-123pay-unlocking-digital-payments-for-feature-phones/](https://urlfiltering.paloaltonetworks.com/test-malware)  
11. What is UPI 123Pay? How to use it and How is it different from the current UPI interface? \- Wint Wealth, accessed March 12, 2026, [https://www.wintwealth.com/blog/what-is-upi-123pay-how-to-use-it-and-how-is-it-different-from-the-current-upi-interface/](https://urlfiltering.paloaltonetworks.com/test-malware)  
12. UPI Circle: How It Works In PhonePe, Google Pay And Other Payment Apps? \- Razorpay, accessed March 12, 2026, [https://razorpay.com/blog/what-is-upi-circle/](https://urlfiltering.paloaltonetworks.com/test-malware)  
13. Pocket money on UPI Circle \- Google Pay Help, accessed March 12, 2026, [https://support.google.com/pay/india/answer/15128460?hl=en](https://urlfiltering.paloaltonetworks.com/test-malware)  
14. How to Link RuPay Credit Card with UPI | Step-by-Step Guide & Benefits \- Paisabazaar, accessed March 12, 2026, [https://www.paisabazaar.com/credit-card/how-to-link-rupay-credit-card-with-upi/](https://urlfiltering.paloaltonetworks.com/test-malware)  
15. UPI Payment Through Credit Card \- Step-by-Step Guide \- Razorpay, accessed March 12, 2026, [https://razorpay.com/learn/upi-payment-through-credit-cards/](https://urlfiltering.paloaltonetworks.com/test-malware)  
16. 1.1% Fees on UPI & Rupay Credit Card UPI Charges: Key Details | Fi Money, accessed March 12, 2026, [https://fi.money/guides/credit-cards/how-to-add-link-rupay-credit-card-with-upi](https://urlfiltering.paloaltonetworks.com/test-malware)  
17. UPI ATM Cash Withdrawal: Withdraw Money Using UPI ATM \- Razorpay, accessed March 12, 2026, [https://razorpay.com/learn/upi-atm-cash-withdrawal/](https://urlfiltering.paloaltonetworks.com/test-malware)  
18. UPI‑ATM Cash Withdrawal: Cardless ATM Guide \- Paytm, accessed March 12, 2026, [https://paytm.com/blog/payments/upi/what-is-upi-atm-cash-withdrawal/](https://urlfiltering.paloaltonetworks.com/test-malware)  
19. How to Modify, Pause, or Cancel Your UPI AutoPay Mandates for Full Control \- Paytm, accessed March 12, 2026, [https://paytm.com/blog/bill-payments/upi-autopay/how-to-modify-pause-or-cancel-your-upi-autopay-mandates-for-full-control/](https://urlfiltering.paloaltonetworks.com/test-malware)  
20. UPI AutoPay in 2025: Setup in Three Steps \- BillCut, accessed March 12, 2026, [https://www.billcut.com/blogs/upi-autopay-in-2025-setup-in-three-steps/](https://urlfiltering.paloaltonetworks.com/test-malware)  
21. UPI Abroad: List of Countries Where Indian Travellers Can Pay Instantly \- Musafir.com, accessed March 12, 2026, [https://in.musafir.com/blog/upi-accepted-countries-for-indians](https://urlfiltering.paloaltonetworks.com/test-malware)  
22. What Does The U16 Error Code Signify In Upi Transactions | Fund Transfer \- Fi.Money, accessed March 12, 2026, [https://fi.money/FAQs/transactions/fund-transfer/what-does-the-u16-error-code-signify-in-upi-transactions](https://urlfiltering.paloaltonetworks.com/test-malware)  
23. What is NPCI UPI Risk Policy? 2026 Rules & Security Guide \- Hero FinCorp, accessed March 12, 2026, [https://www.herofincorp.com/blog/upi-risk-policy](https://urlfiltering.paloaltonetworks.com/test-malware)  
24. Frequently Asked Questions – BHIM App FAQs, accessed March 12, 2026, [https://www.bhimupi.org.in/faq-s](https://urlfiltering.paloaltonetworks.com/test-malware)  
25. NPCI's UDIR \- UPI GRM, accessed March 12, 2026, [https://upigrm.dvararesearch.com/npcis-udir/](https://urlfiltering.paloaltonetworks.com/test-malware)  
26. UPI TPAP Explained: Guide to Third-Party App Providers \- Razorpay, accessed March 12, 2026, [https://razorpay.com/blog/all-you-need-to-know-about-upi-third-party-apps-tpaps/](https://urlfiltering.paloaltonetworks.com/test-malware)  
27. Complaints Handling Policy \- Google Pay, accessed March 12, 2026, [https://pay.google.com/intl/en\_in/about/business/policy/complaints-handling/](https://urlfiltering.paloaltonetworks.com/test-malware)  
28. UPI Fraud: Types & Prevention to Secure Your Account \- Paytm, accessed March 12, 2026, [https://paytm.com/blog/payments/upi/upi-fraud-types-and-prevention-to-secure-your-account/](https://urlfiltering.paloaltonetworks.com/test-malware)  
29. Understanding UPI frauds: Common scams and prevention tips \- Pine Labs, accessed March 12, 2026, [https://www.pinelabs.com/blog/understanding-upi-frauds-common-scams-and-prevention-tips](https://urlfiltering.paloaltonetworks.com/test-malware)  
30. Accept payments with RuPay cards, credit lines & wallets \- Google Pay for Offline Business Help, accessed March 12, 2026, [https://support.google.com/pay-offline-merchants/answer/13591970?hl=en](https://urlfiltering.paloaltonetworks.com/test-malware)  
31. List of Countries Where You Can Use UPI \- Paytm, accessed March 12, 2026, [https://paytm.com/blog/payments/upi/pi-accepted-countries-list/](https://urlfiltering.paloaltonetworks.com/test-malware)  
32. UPI Error Codes and Descriptions | PDF | Payments \- Scribd, accessed March 12, 2026, [https://www.scribd.com/document/701063126/Upi-Response-Codes](https://urlfiltering.paloaltonetworks.com/test-malware)  
33. Error Codes \- UPI \- Digio | Documentation, accessed March 12, 2026, [https://documentation.digio.in/digicollect/upi/error\_codes/](https://urlfiltering.paloaltonetworks.com/test-malware)  
34. UPI Response Codes for H2H/API \- Axis Bank, accessed March 12, 2026, [https://www.axis.bank.in/docs/default-source/default-document-library/sme/upi-response-codes.pdf?sfvrsn=42c4b903\_1](https://urlfiltering.paloaltonetworks.com/test-malware)  
35. UPI Dispute Redressal Mechanism: Your Solution Guide \- Razorpay, accessed March 12, 2026, [https://razorpay.com/blog/upi-dispute-redressal-mechanism/](https://urlfiltering.paloaltonetworks.com/test-malware)
