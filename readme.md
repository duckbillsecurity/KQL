## Basic KQL Syntax and Operations

### Overview of KQL Syntax

Kusto Query Language (KQL) is a powerful language used for analyzing and extracting insights from data, particularly in security and threat hunting scenarios. The syntax is designed to be easy to read and write, making it accessible for users with various levels of programming experience.

### Key Characteristics of KQL Syntax

- **Case Insensitivity**: KQL is case-insensitive for keywords, operator names, and function names.
- **Tabular Data Format**: KQL queries operate on tabular data (tables) and return results in table format.
- **Piping**: Uses the pipe character (`|`) to pass the results of one command as the input to the next.
- **Comments**: Use `//` for single-line comments and `/* */` for multi-line comments.

### Common KQL Commands and Operators

#### 1. `search`
- Used for free-text search across all tables.
- Example: `search "error 404"`

#### 2. `where`
- Filters rows based on the specified condition.
- Example: `SecurityEvent | where EventID == 4625`

#### 3. `project`
- Selects which columns to display in the results.
- Example: `SecurityEvent | project AccountName, EventID`

#### 4. `summarize`
- Aggregates data based on specified grouping.
- Example: `SecurityEvent | summarize count() by EventID`

#### 5. `join`
- Combines rows from two or more tables based on a related column.
- Example: `SecurityEvent | join kind=inner AuditLogs on $left.EventID == $right.EventID`

#### 6. `extend`
- Creates new columns by calculating values from existing columns.
- Example: `SecurityEvent | extend NewColumn = AccountName + "_suffix"`

#### 7. `top`
- Returns the first N records sorted by a given expression.
- Example: `SecurityEvent | top 10 by TimeGenerated`

#### 8. `sort`
- Sorts the rows in the table based on specified columns.
- Example: `SecurityEvent | sort by EventID desc`

#### 9. `count`
- Returns the count of rows.
- Example: `SecurityEvent | count`

#### 10. `distinct`
- Returns unique rows.
- Example: `SecurityEvent | distinct AccountName`
