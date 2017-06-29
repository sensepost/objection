var bar = eval(["{{ pattern }}"]);

Memory.writeByteArray(ptr("{{ destination }}"), bar);
