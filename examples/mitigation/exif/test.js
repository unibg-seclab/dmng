let p = Deno.run({ cmd: ["exiftool", "./input_images/poc.jpg"] });
await p.status();
