import * as bcrypt from 'bcrypt';

export const compareHash = (input: string, candidate: string): boolean => {
    return bcrypt.compareSync(input, candidate);
};

export const generateHash = async (str: string) => {
    const salt = await bcrypt.genSalt(10)
    return await bcrypt.hash(str, salt);
}