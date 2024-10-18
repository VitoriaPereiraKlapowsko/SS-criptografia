import { Request, Response } from 'express';
import { User } from '../models/User';
import nodemailer, { SendMailOptions } from 'nodemailer';
import { Jwt } from 'jsonwebtoken';
const bcrypt = require('bcrypt');

export const register = async (req: Request, res: Response) => {

    const { email, password, name, discipline } = req.body;

    if (email && password && name && discipline) {
            try {
                let hasUser = await User.findOne({where: {email}});

                if (!hasUser) {
                    const saltRounds = 10;
                    const hashedPassword = await bcrypt.hash(password, saltRounds);
                
                    let newUser = await User.create({
                        email,
                        password: hashedPassword,
                        name,
                        discipline
                    });
                    res.status(201).json({message: 'Usuário cadastrado com sucesso.', newUser});
                }
            } catch (error){
                console.error('Erro ao cadastrar usuário:', error);
                res.status(500).json({error: 'Erro interno ao processar o registro.'});
            }

        } else {
            res.status(400).json({ error: 'E-mail, senha, nome e/ou disciplina não fornecidos' });
        }
    }


export const login = async (req: Request, res: Response) => {
    if (req.body.email && req.body.password) {
        let email: string = req.body.email;
        let password: string = req.body.password;

        let user = await User.findOne({
            where: { email, password }
        });

        if (user) {
            res.json({ status: true });
            return;
        }
    }

    res.json({ status: false });
}




export const listAll = async (req: Request, res: Response) => {
    let users = await User.findAll();

    res.json({ users });
}


export const forgotPassword = async (req: Request, res: Response) => {
    const { email } = req.params;

    try {
        const hasUser = await User.findOne({ where: { email } });

        if (!hasUser) {
            return res.status(404).json({ error: 'Usuário não encontrado.' });
        }
        const randomPassword = Math.random().toString(36).slice(-8);
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(randomPassword, saltRounds);

        hasUser.password = hashedPassword;
        await hasUser.save();
    
        const transporter = nodemailer.createTransport({
            host: 'sandbox.smtp.mailtrap.io',
            port: 2525,
            auth: {
                user: '3c06f9dbdde467',
                pass: 'b338ed92a62e61',
            },
        });

        const mailOptions = {
            from: 'seu-email@dominio.com',
            to: email,
            subject: 'Recuperação de senha',
            text: `Sua nova senha é: ${randomPassword}`, 
        };
        
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('Erro ao enviar o e-mail:', error);
                res.status(500).json({ error: 'Erro ao enviar e-mail de recuperação de senha.' });
            } else {
                console.log('E-mail enviado:', info.response);
                res.status(200).json({ message: 'Nova senha enviada para o seu e-mail.' });
            }
        });
    
    } catch (error) {
        console.error('Erro ao recuperar a sennha:', error);
        res.status(500).json({ error: 'Erro interno ao processar a recuperação de senha.' });
    } 
}