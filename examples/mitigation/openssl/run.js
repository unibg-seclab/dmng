var p;

p = Deno.run({ cmd: ["./poc.sh"] });
await p.status();
