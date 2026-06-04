Technique_id: T1407
Nombre: Download New Code at Runtime
Detectable_red: Si
Muestras:
  - SHA-256: ...
    1. NOMBRE: 01-Anubis-Fattura
    2. FAMILIA: Anubis
    3. PCAP: No
    4. EVIDENCIA: None
    5. FUENTE: https://github.com/Juan-dpa/Anubis_Fattura
    6. PLATAFORMA: Android
    7. COMENTARIO: No se ha confirmado la técnica en dicha muestra hasta el momento.

  - SHA-256: ...
    1. NOMBRE: 02-Anubis
    2. FAMILIA: Anubis
    3. PCAP: No
    4. EVIDENCIA: None
    5. FUENTE: https://tria.ge/260510-z3bq9ah13l
    6. PLATAFORMA: Android
    7. COMENTARIO: El triaje contiene una captura, la cual requiere ser validada. Afirma la técnica en triaje, pero en base a modulos java lícitos. Es verdad que algunos están relacionados con criptografía (bouncycastle). Lo más probable es que desde la captura no se pueda obtener la técnica, y que se requiera más esfuerzo.

  - SHA-256: ...
    1. NOMBRE: 03-Anubis
    2. FAMILIA: Anubis
    3. PCAP: No
    4. EVIDENCIA: None
    5. FUENTE: https://tria.ge/260511-q8w5pse13p
    6. PLATAFORMA: Android
    7. COMENTARIO: En este caso no se afirma la técnica. Debido a que Anubis es conocido y referenciado por la MITRE MOBILE para esta técnica, hay confianza en que la integre.

  - SHA-256: ...
    1. NOMBRE: 04-Anubis
    2. FAMILIA: Anubis
    3. PCAP: No
    4. EVIDENCIA: None
    5. FUENTE: https://tria.ge/260522-3e6hhaax6v/behavioral1
    6. PLATAFORMA: Android
    7. COMENTARIO: En este caso no se afirma la técnica. Debido a que Anubis es conocido y referenciado por la MITRE MOBILE para esta técnica, hay confianza en que la integre.

  - SHA-256: ...
    1. NOMBRE: NID-NioServ
    2. FAMILIA: NioServ*
    3. PCAP: No
    4. EVIDENCIA: None
    5. FUENTE: https://www.malware-traffic-analysis.net/2014/03/06/index.html
    6. PLATAFORMA: Android
    7. COMENTARIO: Obtenido de la página malware-traffic-analysis. Parece representar la técnica. Requiere validación.

  - SHA-256: ...
    1. NOMBRE: 01-Cerberus
    2. FAMILIA: Cerberus
    3. PCAP: No
    4. EVIDENCIA: Muy alta, descarga un fichero JSON. Dicho fichero al ser descargado claramente muestra técnicas de entropía y ocupa un tamaño excesivo para ser JSON. No solo eso, posteriomente se genera un .vdex, lo cual implica que el Dexloader ha hecho efecto.
    5. FUENTE: https://tria.ge/260413-wt2pjadv6l/behavioral1
    6. PLATAFORMA: Android
    7. COMENTARIO: Trae un PCAPNG, falta validar pero mucho potencial.

  - SHA-256: ...
    1. NOMBRE: 02-Cerberus
    2. FAMILIA: Cerberus
    3. PCAP: No
    4. EVIDENCIA: Muy alta, descarga un fichero JSON. No se ha validado el JSON ni se observa en triaje que genere un vdex, pero el funcionamiento apunta al anterior.
    5. FUENTE: https://tria.ge/260522-3g744sgt3k/behavioral1
    6. PLATAFORMA: Android
    7. COMENTARIO: Trae un PCAPNG, falta validar pero mucho potencial.

  - SHA-256: ...
    1. NOMBRE: 01-Chameleon-Github
    2. FAMILIA: Chameleon
    3. PCAP: No
    4. EVIDENCIA: Ninguna
    5. FUENTE: https://github.com/IHbib/chameleon-android-malware-samples
    6. PLATAFORMA: Android
    7. COMENTARIO: Poca información.

  - SHA-256: ...
    1. NOMBRE: 02-Chameleon
    2. FAMILIA: Chameleon
    3. PCAP: No
    4. EVIDENCIA: tria.ge marca la técnica y muestra los JSON descargados. Alta evidencia.
    5. FUENTE: https://tria.ge/251029-xbm9vsbl8v/behavioral1
    6. PLATAFORMA: Android
    7. COMENTARIO: Igual que los casos de Cerberus, requiere ser validado.

  - SHA-256: ...
    1. NOMBRE: 01-Mandrake
    2. FAMILIA: Mandrake
    3. PCAP: No
    4. EVIDENCIA: 
    5. FUENTE: https://tria.ge/220627-m3fnzsafbm/behavioral1
    6. PLATAFORMA: Android
    7. COMENTARIO: Obtenido a partir del segundo hash MD5 de la referencia MITRE.

  - SHA-256: ...
    1. NOMBRE: 02-Mandrake
    2. FAMILIA: Mandrake
    3. PCAP: No
    4. EVIDENCIA: 
    5. FUENTE: https://tria.ge/240517-wxpt5scc5v/behavioral1
    6. PLATAFORMA: Android
    7. COMENTARIO: Obtenido a partir de hash MD5 de la referencia MITRE. 

  - SHA-256: ...
    1. NOMBRE: 03-Mandrake
    2. FAMILIA: Mandrake
    3. PCAP: No
    4. EVIDENCIA: 
    5. FUENTE: https://tria.ge/250323-ten4saznw5/behavioral1
    6. PLATAFORMA: Android
    7. COMENTARIO: Obtenido a partir de hash MD5 de la referencia MITRE. 

  - SHA-256: ...
    1. NOMBRE: 01-Sharkbot
    2. FAMILIA: Sharkbot
    3. PCAP: Si
    4. EVIDENCIA: Completa. Leer el readme asociado a la muestra.
    5. FUENTE: https://github.com/Juan-dpa/Sharkbot-Malware
    6. PLATAFORMA: Android
    7. COMENTARIO: Debido a que se necesitó emular el C2, he optado por refijar la clave de cifrado dinámica del código, a través de parche. Por lo demás la firma es exacta a la original.

  