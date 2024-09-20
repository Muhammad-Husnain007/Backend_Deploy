import mongoose from 'mongoose';
import { DB_NAME } from '../constants.js';

const Connection = async () => {
  try {
    const connectionInstance = await mongoose.connect(`${process.env.MONGODB_URL}${DB_NAME}`);
    
    // Log a success message with the host of the connected MongoDB instance.
    console.log(`MongoDB connected !! DB HOST: ${connectionInstance.connection.host}`);
  } catch (error) {
    console.log("MONGODB connection FAILED ", error);
    // Exit the process with a failure code (1) if the connection fails.
    process.exit(1);
  }
};

export default Connection;
