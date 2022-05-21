import sequelize from '../db';
import { DataTypes } from 'sequelize';

export interface IUser {
    id: string;
    username: string;
    password: string;
    photo: string;
}

export const User = sequelize.define('user', {
    id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    username: { type: DataTypes.STRING, unique: true },
    password: { type: DataTypes.STRING },
    photo: { type: DataTypes.STRING },
});
