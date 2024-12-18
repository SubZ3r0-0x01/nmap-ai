# Crash Report: SQL Injection (Union-Based and Time-Based)

### **Severity:** Critical  
### **Exploitability:** Easy  
### **Function / Target:** Taxonomy  

---

## **Description**  
The application’s reliance on weak SQL query construction and inadequate input validation has introduced a critical vulnerability to SQL injection attacks. This flaw allows attackers to exploit union-based and time-based techniques to manipulate SQL queries, gain unauthorized access to sensitive data, and compromise the database's integrity. The vulnerability was identified in the **"ViewType"** parameter, which lacks proper sanitization and validation, enabling malicious payloads to bypass security mechanisms. Key functions such as **findByWhereClause** further contribute to the issue by directly integrating unsanitized user input into SQL statements.

---

## **Risk / Impact**  
Exploitation of this SQL injection vulnerability could result in:  
- **Data Exfiltration:** Unauthorized access to sensitive user and business data.  
- **Database Manipulation:** Unauthorized transactions with potential financial and operational implications.  
- **Service Disruption:** Database corruption or downtime, compromising availability.  
- **Regulatory Risks:** Non-compliance with data protection standards, risking hefty penalties.  
- **Reputational Damage:** Loss of user trust due to breaches and data leaks.  

---

## **Evidence**  

### 1. **Application Version Analysis**  
- The vulnerable application version is **6.4**.

### 2. **Initial Observation with SilverAdmin User**  
- Log in with the SilverAdmin account and navigate to **Back office > Taxonomy > Axis**. The **Primary topics** view exhibited abnormal behaviors when analyzing requests.

### 3. **Request Analysis - Parameter "ViewType"**  
- Review of the "ViewType" parameter showed improper input validation during server-side processing.  

### 4. **Sink Analysis for ViewType Parameter**  
- The parameter interacts with the SQL layer in a manner susceptible to injection.  

### 5. **Query Analysis with Supplied Input**  
- Injecting malicious input into the parameter demonstrated SQL query manipulation potential.  

### 6. **Vulnerable Function: findByWhereClause**  
- Identified as a critical flaw: the function directly constructs SQL queries using user input without adequate sanitization.  

### 7. **CheckValueForInjection Function**  
- Although present, the **CheckValueForInjection** function failed to prevent malicious payloads from bypassing injection checks.  

### 8. **Code Inspection - SQL Injection Patterns**  
- The codebase initializes Pattern objects for SQL injection detection, but implementation gaps allow exploitation.

### 9. **Time-Based SQL Injection Verification**  
- Payload:  
  ```sql
  P'%3bSelect+PG_SLEEP(10)--
