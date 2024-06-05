# Preprocesador PCAP

## Uso
### Como script
Puedes ejecutar la herramienta como un script con `python preprocess.py`.
La herramienta espera encontrar los archivos `.pcap` en el mismo directorio que el script con el siguiente formato:

`{dataset}-{tipo}.pcap`

El script se encarga automaticamente de inferir `dataset` y `tipo` basándose en el nombre del archivo.

### Como libreria

El código también se puede usar como librería en otros scripts/jupyter notebooks importando las funciones `per_packet_process_pcap` y `per_transact_process_df`, que se encargas de generar el dataframe para cada archivo pcap por paquetes y por transacciones.

La signature de las funciones es:

```python
def per_packet_process_pcap(fname: str, label: str) -> pd.DataFrame:
    ...

def per_transact_process_df(df: pd.DataFrame) -> pd.DataFrame:
    ...
```

En otras palabras, la función por processo recibe el path al archivo y la label asociada con ese archivo, y retorna un DataFrame. 
La función para transacciones recibe el DataFrame generado con la función anterior y la procesa en transacciones

## Notas importantes

El comportamiento por defecto es asumir que la transferencia de archivos se hace sobre una sola conexión y por tanto, eliminamos los primeros y últimos 3 paquetes que corresponden a gestión de la conexión (SYN-SYNACK-ACK y SYN-FINACK-ACK respectivamente). Este comportamiento se controla con `transfered_in_one_go=True` en la función `per_packet_process_pcap`.

Se ignoran todos los paquetes TCP que no tengan la flag Push activa, para evitar incluir parte del ARP spoof.

Debido a la definición del atributo `flow_duration`, que es la diferencia entre un paquete y el anterior, el primer paquete de una captura siempre tendrá `flow_duration=NaN` porque no se conoce la timestamp del paquete previo.
