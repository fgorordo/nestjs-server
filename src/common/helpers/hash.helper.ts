import * as bcrypt from 'bcrypt';

export const compareHash = async (input: string, candidate: string): Promise<boolean> => {
    return await bcrypt.compare(input, candidate);
};

export const generateHash = async (str: string) => {
    const salt = await bcrypt.genSalt(10)
    return await bcrypt.hash(str, salt);
}