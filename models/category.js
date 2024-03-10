const mongoose = require("mongoose");
const Schema = mongoose.Schema;

// Product schema
const productSchema = new Schema({
  name: { type: String, required: true },
  imageUrl: { type: String },
  price: { type: Number, required: true },
  quantity: { type: Number }, // Add quantity field
});

// Cart item schema
const cartItemSchema = new Schema({
  product: productSchema,
  quantity: { type: Number, required: true },
  userEmail: { type: String, required: true }, // User's email
});

// Category schema
const categorySchema = new Schema({
  title: { type: String, required: true },
  image: { type: String, required: true },
  products: [productSchema], // Embedded product documents
});

const orderSchema = new Schema({
  userId: { type: Schema.Types.ObjectId, ref: "User" }, // Reference to User model
  userEmail: { type: String }, // User's email
  userName: { type: String }, // User's name
  products: [productSchema], // Array of products in the order
  totalPrice: { type: Number, required: true },
  createdAt: { type: Date, default: Date.now },
  status: { type: String, default: "pending" },
});

const Order = mongoose.model("Order", orderSchema);
const Category = mongoose.model("Category", categorySchema);
const Product = mongoose.model("Product", productSchema);
const CartItem = mongoose.model("CartItem", cartItemSchema);

module.exports = {
  Category,
  Product,
  Order,
  CartItem,
};
