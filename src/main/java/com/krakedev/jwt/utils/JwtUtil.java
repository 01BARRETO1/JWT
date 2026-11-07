package com.krakedev.jwt.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;


import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

public class JwtUtil {
	
	private static final Logger logger =
            LoggerFactory.getLogger(JwtUtil.class);
	
	private static final String CLAVE_SECRETA="EstaEsUnaClaveSuperSecretaYMuyLarga0987654321!";
	
	//Identificador de quién está creando este token,
	//le ayuda al backend, verifica que el token fue generado por el mismo
	private static final String EMISOR = "KrakeDevBackend";
	
	//30 minutos × 60 segundos × 1000 milisegundos = 30 minutos
	private static final long TIEMPO_EXPIRACION = 30 * 60 * 1000;
	
	//método para generar un JSON web token, firmado que contiene la informacion del usuario.
	public static String generarToken(String username, String rol) {
		
		//Descargado de la biblioteca jwt,
		//Variable de tipo, algoritmo
		//(HMAC256)->para poderlo firmar  --> método .HMAC256
		Algorithm algoritmo = Algorithm.HMAC256(CLAVE_SECRETA);
		
		
		long tiempoActual = System.currentTimeMillis();
		
		Date fechaExpiracion = new Date(tiempoActual+ TIEMPO_EXPIRACION);
		
		
		//Generar token, método de la librería jwt -->  JWT.create()
		//1.- Quién es el creador de este token? --> .withIssuer(EMISOR)
		//2.-Cuál es el dueño, usuario ó persona -->  .withSubject(username)
		//3.-fecha de emisión--> .withIssuedAt(new Date(tiempoActual))
		//4.- Fecha de expiracion--> .withExpiresAt(fechaExpiracion)
		//5.- se puede agregar datos personalizados llamdos clain ó,
		// 5.- reclamaciones podemos agregar el rol del usuario, PERO esta informacion,
		// 5.- es publica, solo codificada en base 64, NO SE DEBE PONER CONTRASEÑAS
		// 5.- Reclamación --> .withClaim("rol", rol)
		//6.- Firma--> .sign(algoritmo)
		String tokenGenerado = JWT.create().withIssuer(EMISOR).withSubject(username)
				.withIssuedAt(new Date(tiempoActual)).withExpiresAt(fechaExpiracion)
				.withClaim("rol", rol).sign(algoritmo);
		
		return tokenGenerado; 
	}
	
	//Función para que valide el token que está recibiendo
	//retorne la informacion decodíficada, si es válido
	//Nos devuelve el tipo JSON web token, decodificado
	//Tipo de dato--> DecodedJWT
	public static DecodedJWT validarToken(String token) {
		
		try {
			//Variable de tipo, algoritmo
			Algorithm algoritmo = Algorithm.HMAC256(CLAVE_SECRETA);
			
			//Objeto verificador, que verificque la firma, usando el algoritmo,
			//y que verificque que el emisor sea el correcto
			//Variable de la libreria JWT-interface ,  -->JWTVerifier
			//JWT.require(algoritmo) --> algoritmo
			//recibe el emisor paar validar que sea el mismo --> .withIssuer(EMISOR)
			//Para que lo construya --> .build() 
			JWTVerifier verificador = JWT.require(algoritmo).withIssuer(EMISOR).build();
			
			//Método de verificar Token, compara la firma.. Matemáticamente
			//comapara la fecha actual y fecha de expiración 
			DecodedJWT tokenDecodificado = verificador.verify(token);
			
			//return token para leer la información, solo si no está modificado
			return tokenDecodificado;
		}catch (Exception e) {
		    logger.error("Error de validación del Token: {}", e.getMessage());
		    return null;
		}
	}

}
