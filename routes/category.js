const express = require('express');
const router = express.Router();
const { authUser,authAdmin } = require('../middleware/auth');
const { Category, Product } = require('../models/category');

// Get all categories (accessible to all users)
router.get('/categories',  async (req, res) => {
  try {
    const categories = await Category.find();
    res.status(200).json(categories);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get all products (accessible to all users)
router.get('/products',  async (req, res) => {
  try {
    const products = await Product.find();
    res.status(200).json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
router.post('/categories', authAdmin, async (req, res) => {
    try {
      const category = new Category(req.body);
      await category.save();
      res.status(201).json(category);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
  router.get("/categorie", async (req, res) => {
    try {
      const categories = await Category.find().populate("products");
      res.status(200).json(categories);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  router.get('/products/:categoryTitle', async (req, res) => {
    const categoryTitle = req.params.categoryTitle;
  
    try {
      // Fetch products based on the provided category title
      const category = await Category.findOne({ title: categoryTitle });
      if (!category) {
        return res.status(404).json({ message: 'Category not found' });
      }
      res.status(200).json(category.products);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  
  // Delete a category by ID (accessible to admin only)
  router.delete('/categories/:categoryId', authAdmin, async (req, res) => {
    try {
      const category = await Category.findByIdAndDelete(req.params.categoryId);
      if (!category) {
        return res.status(404).json({ error: 'Category not found' });
      }
      res.status(200).json({ message: 'Category deleted successfully' });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  
  // Update a category by ID (accessible to admin only)
  router.put('/categories/:categoryId', authAdmin, async (req, res) => {
    try {
      const category = await Category.findByIdAndUpdate(req.params.categoryId, req.body, { new: true });
      if (!category) {
        return res.status(404).json({ error: 'Category not found' });
      }
      res.status(200).json(category);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
  
  // Add a new product (accessible to admin only)
  router.post('/products', authAdmin, async (req, res) => {
    try {
      const product = new Product(req.body);
      await product.save();
      res.status(201).json(product);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
  
  // Delete a product by ID (accessible to admin only)
  router.delete('/products/:productId', authAdmin, async (req, res) => {
    try {
      const product = await Product.findByIdAndDelete(req.params.productId);
      if (!product) {
        return res.status(404).json({ error: 'Product not found' });
      }
      res.status(200).json({ message: 'Product deleted successfully' });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  
  // Update a product by ID (accessible to admin only)
  router.put('/products/:productId', authAdmin, async (req, res) => {
    try {
      const product = await Product.findByIdAndUpdate(req.params.productId, req.body, { new: true });
      if (!product) {
        return res.status(404).json({ error: 'Product not found' });
      }
      res.status(200).json(product);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
module.exports = router;
