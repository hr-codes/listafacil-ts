import { Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const prisma = new PrismaClient();

class AuthController {
  public signIn = async (req: Request, res: Response) => {
    const { email, password } = req.body;

    await prisma.user
      .findUnique({
        where: {
          email: email,
        },
      })
      .then(async (response) => {
        if (!response) {
          return res.status(404).json({
            message: "User not found.",
          });
        }

        if (response.password) {
          const match = await bcrypt.compare(password, response.password);

          if (match) {
            const tokens = this.generateTokens(response.id);

            return res.status(200).json({
              access_token: tokens.accessToken,
              refresh_token: tokens.refreshToken,
              expires_in: process.env.TOKEN_EXPIRATION_TIME,
              expires_in_unity: "seconds",
            });
          }

          return res.status(401).json({
            message: "Password is not valid",
          });
        }
      })
      .catch(() => {
        return res.status(400).json({
          message: "error on fetch user",
        });
      });
  };

  public signUp = async (req: Request, res: Response) => {
    const { name, email, password } = req.body;

    const saltRounds = 10;

    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);

    await prisma.user
      .create({
        data: {
          name: name,
          email: email,
          password: hashedPassword,
        },
      })
      .then((data) => {
        return res.json({
          data,
          message: "Sucesso ao criar.",
        });
      })
      .catch((err) => {
        return res.json({
          message: `Erro ao criar usuário: ${err}`,
        });
      });
  };

  public refreshToken = (req: Request, res: Response) => {
    try {
      const { refresh_token } = req.body;

      const decoded = jwt.verify(refresh_token, process.env.APP_SECRET);

      const userId = decoded.id;

      const tokens = this.generateTokens(userId);

      return res.status(200).json({
        access_token: tokens.accessToken,
        refresh_token: tokens.refreshToken,
        expires_in: process.env.TOKEN_EXPIRATION_TIME,
        expires_in_unity: "seconds",
      });
    } catch (error) {
      return res.status(400).json({
        message: `"Erro ao verificar o refresh_token: ${error}`,
      });
    }
  };

  private generateTokens = (userId: Number) => {
    const accessToken = jwt.sign({ id: userId }, process.env.APP_SECRET, {
      expiresIn: process.env.TOKEN_EXPIRATION_TIME,
    });
    const refreshToken = jwt.sign({ id: userId }, process.env.APP_SECRET, {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRATION_TIME,
    });

    return { accessToken, refreshToken };
  };
}

export const authController = new AuthController();
