import { BeforeInsert, BeforeUpdate, Column, CreateDateColumn, DeleteDateColumn, Entity, PrimaryGeneratedColumn, UpdateDateColumn } from 'typeorm';
import * as bcrypt from 'bcrypt';

@Entity('users')
export class User {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column('text', {nullable: false, unique: true})
    email: string;

    @Column('text', {nullable: false})
    password: string

    @Column('text', {nullable: true})
    rtHash: string;

    @Column('bool',{default: true})
    isActive: boolean;

    refreshToken?: string;

    @CreateDateColumn()
    createdAt: Date;

    @UpdateDateColumn()
    updatedAt: Date;

    @DeleteDateColumn()

    deletedAt: Date;

    @BeforeInsert()
    hashPassword() {
        const salt = bcrypt.genSaltSync(10);
        this.password = bcrypt.hashSync(this.password, salt);
    };

    @BeforeInsert()
    normalizeValues() {
        this.email = this.email.trim().toLowerCase();
    }

    @BeforeUpdate()
    beforeUpdate() {
        this.normalizeValues();
    };



}
