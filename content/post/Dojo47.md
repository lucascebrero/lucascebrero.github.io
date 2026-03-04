---
title: "Dojo #47 APICrash"
date: 2026-02-08T01:23:53Z
categories: [ "writeup" ]
---

## Description
The application exposes two APIs, `/api/getposts` and `/api/updatepost`. The first endpoint returns a list of all posts in a JSON response containing each post's `id` and `content`. The latter allows users to update the content of a specific post by providing its identifier.

Internally, the application processes these requests using GraphQL and a TinyDB backend for storing the posts.

It was found that the API is vulnerable to a race condition caused by concurrent database writes. By triggering multiple `updatePost` mutations in a single GraphQL request, an attacker can corrupt the underlying TinyDB database causing read operations to fail, making the application unavailable.

## Code Analysis
The application uses a lightweight document-oriented database called TinyDB and processes GraphQL queries using the Graphene library. For each request, two GraphQL queries are executed sequentially. The first one executes a user-controlled query, stored in the `query` variable. During the execution of this query, multiple threads may be spawned to handle `updatePost` mutations.

After all spawned threads have finished, the application executes a second query, `{ getPosts { id content } }` which is fixed and not directly influenced by user input, and returns the results in the HTML response.

As it can be seen in the `GraphqlQuery` class definition, there is a method for updating a post, `update_post_in_db` which is not called directly in the main application flow but can be triggered through the user input.

This function can be invoked by the user using the following GraphQL mutation:
```graphql
{ first: updatePost(id: 1, content: "Test1 ")}
```

When this mutation is executed, the `resolve_update_post` resolver spawns a new thread that calls `update_post_in_db`, which performs a read-modify-write operation on the TinyDB database without any synchronization.

```python
class GraphqlQuery(graphene.ObjectType):

    get_posts = graphene.List(Post)
    update_post = graphene.Boolean(id=graphene.Int(), content=graphene.String())

    def update_post_in_db(id, content):
        node = db.search(tinydb.Query().id == int(id))
        if node == []:
            return False
        else:
            node[0]['content'] = content
            db.update(node[0], tinydb.Query().id == int(id))
            return True

    def resolve_update_post(self, info, id, content):
        t = threading.Thread(target=GraphqlQuery.update_post_in_db, args=[id, content])
        t.start()
        threads.append(t)

    def resolve_get_posts(self, info):
        return db.all()

def main():
    # User input (GraphQL query)
    query = unquote("test")

    schema = graphene.Schema(query=GraphqlQuery)
    schema.execute(query)

    # Wait for all GraphQL processes to finish
    for t in threads:
        t.join()

    result = schema.execute("{ getPosts { id content } }")

    # Check if the JSON in the posts are malformed
    posts = {}

    # TODO : Random crashes appear time to time with same input, but different error. We working on a fix.
    if result.errors:
        posts = json.dumps({"FLAG": os.environ["FLAG"]}, indent=2)
    else:
        posts = json.dumps(result.data, indent=2)

    print(template.render(posts=posts))

main()
```

## Exploitation
Since the `updatePost` mutation spawns threads that perform concurrent write operations and TinyDB is not thread-safe, a race condition can be exploited to corrupt the database by triggering concurrent `updatePost` mutations. When multiple threads attempt to write the database file at the same time, the JSON file gets corrupted, resulting in invalid JSON.

GraphQL allows sending a single query containing multiple `updatePost` mutations as follows:
```graphql
{first: updatePost(id:1, content:"test") second: updatePost(id:2, content:"test2") third: updatePost(id:3,content:"test3")}
```

This causes multiple threads to write to the database simultaneously, corrupting the underlying JSON file. Then, when the application executes the hardcoded query to retrieve all posts from the database, TinyDB fails to parse the corrupted data, resulting in an error that triggers the flag.

![](/images/dojo47/Flag.png)

## Remediation
There are several possible approaches to remediate this issue. Since TinyDB is not thread-safe, concurrent write operations should be avoided and database updates should be performed in a single thread.

For example, removing the user of threading in the `resolve_update_post` method and executing `update_post_in_db` synchronously prevents database corruption
```python
def resolve_update_post(self, info, id, content):
     GraphqlQuery.update_post_in_db(id,content)
```

![](/images/dojo47/Fix.png)

Alternatively, if concurrency is required, a locking mechanism such as `threading.Lock` can be implemented to ensure that write operations are executed atomically. 

Finally, if the application design requires concurrent database access, migrating to a database that provides built-in concurrency control should be considered, as TinyDB does not support safe concurrent writes by default.
