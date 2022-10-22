package com.tpe.dto.request;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

    @NotBlank(message="Please Provide FirstName")
	private String firstName;
	
    @NotBlank(message="Please Provide LastName")
	private String lastName;
	
    @NotBlank(message="Please Provide UserName")
    @Size(min=5,max=10, message="Please provide a User Name min=5, max=10 chars long")
	private String userName;

    @NotBlank(message="Please Provide Password")
	private String password;
	
}
