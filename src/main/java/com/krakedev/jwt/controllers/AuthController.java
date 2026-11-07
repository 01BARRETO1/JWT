package com.krakedev.jwt.controllers;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.repositories.UsuarioRepository;
import com.krakedev.jwt.services.UsuarioService;
import com.krakedev.jwt.utils.JwtUtil;



@RestController
@RequestMapping("/auth")
public class AuthController {

	private final UsuarioService usuarioService;
	
	private final UsuarioRepository usuarioRepository;

	public AuthController(UsuarioService usuarioService, UsuarioRepository usuarioRepository ) {
		super();
		this.usuarioService = usuarioService;
		this.usuarioRepository=usuarioRepository;
	}
	
	@PostMapping("/registrar")//método registrar
	public ResponseEntity<?> registra(@RequestBody Usuario usuario){
		
		try {
			Usuario usuarioNuevo = usuarioService.guardar(usuario);
			//ResponseEntity de estado creado
			return ResponseEntity.status(HttpStatus.CREATED).body(usuarioNuevo);
			
		} catch (Exception e) {
			//INTERNAL_SERVER_ERROR
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("Error al registrar usuario: " + e.getMessage());
		}
		
	}
	
	//Método para login
	// clave:valor --> es un tipo de dato -> Map<String, String> -> y  se llama -> credenciales
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody Map<String, String> credenciales){
		String username = credenciales.get("username");
		String password = credenciales.get("password");
		
		boolean autenticado = usuarioService.autenticar(username, password);
		
		if(autenticado) {
			//Buscamos a este usuario en la base de datos/ .get() para recuperarlo 
			Usuario usuario =usuarioRepository.findByUsername(username).get();
			
			//TOKENN
			String token = JwtUtil.generarToken(usuario.getUsername(), usuario.getRol());
			
			return ResponseEntity.ok(Map.of("Login", token));
		}else {
			
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario o contraseña incorrecta");
		}
	}
	
	
	// Método para probar el token
	@GetMapping("/perfil")
	public ResponseEntity<?> verPerfil(@RequestHeader(value = "Authorization", required = false) String authHeader) {
		if (authHeader == null || !authHeader.startsWith("Bearer ")) {

			return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
					.body("Acceso Denegado: Debes proveer un token Bearer valido en la cabecera Authorization");
		}

		// elimina-> substring(7)
		String token = authHeader.substring(7);

		DecodedJWT datosToken = JwtUtil.validarToken(token);

		if (datosToken == null) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Acceso denegado, token invalido o Expirado");
		}

		String usuario = datosToken.getSubject();

		String rol = datosToken.getClaim("rol").asString();

		return ResponseEntity.ok(Map.of("Mensaje", "Bienvendio al sistema protegido por jwt", "Usuario", usuario, "Rol",
				rol, "Estatus", "Autenticado exitosamente"

		));
	}
	
}
