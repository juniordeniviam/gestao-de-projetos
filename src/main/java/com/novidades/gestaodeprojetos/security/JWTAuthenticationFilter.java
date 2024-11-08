package com.novidades.gestaodeprojetos.security;

import java.io.IOException;
import java.util.Collections;
import java.util.InputMismatchException;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter{
	
	@Autowired
	private JWTService jwtService;
	
	@Autowired
	private CustomUserDetailsService customUserDetailsService;
	
	// Método principal onde toda requisição bate antes de chegar no nosso endpoint.
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) 	throws ServletException, IOException {
		
		// pego o token de dentro da requisição
		String token = obterToken(request);
		
		// Pego o id do usuário que está dentro do token
		Optional<Long> id = jwtService.obterIdDoUsuario(token);
		
		// Se não achou o id, é porque o usuário não mandou o token correto.
		if(!id.isPresent()) {
			throw new InputMismatchException("Token inválido!");
		}
		
		// Pego o usuario dono do token pelo seu id.
		UserDetails usuario = customUserDetailsService.obterUsuarioPorId(id.get());
		
		// Neste trecho verificamos se o usuário está autenticado ou não.
		// Neste trecho tambem poderia ser validado as permissões.
		UsernamePasswordAuthenticationToken autenticacao = new UsernamePasswordAuthenticationToken(usuario, null, Collections.emptyList());
		
		// Mudando a autenticação para a própria requisição
		autenticacao.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
		
		// Repasso a autenticação para o contexto do security.
		// A partir de agora o spring toma conta de tudo para mim :D
		SecurityContextHolder.getContext().setAuthentication(autenticacao);
		
	}
	
	private String obterToken(HttpServletRequest request) {
		
		String token = request.getHeader("Authorization");
		
		if(StringUtils.hasText(token)) {
			return null;
		}
		
		return token.substring(7);
	}

}
