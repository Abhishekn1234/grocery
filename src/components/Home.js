import React, { useState, useEffect } from "react";
import { Container, Card, Modal, Button, Form, Col, Row } from "react-bootstrap";
import { Link, useNavigate } from "react-router-dom";
import { AiOutlineCloseCircle } from "react-icons/ai";
import axios from "axios";
import Carousell from "./Carousel";
import { useCart } from "./ContextReducer";
import Footer from "./Footer";

export default function Home() {
  const navigate = useNavigate();
  const { addToCart } = useCart();
  const [showModal, setShowModal] = useState(false);
  const [selectedProduct, setSelectedProduct] = useState(null);
  const [quantity, setQuantity] = useState(1);
  const [searchQuery, setSearchQuery] = useState("");
  const [categories, setCategories] = useState([]);
  const handleClose = () => setShowModal(false);

  useEffect(() => {
    const fetchCategories = async () => {
      try {
        const response = await axios.get("http://localhost:5000/categories");
        setCategories(response.data);
      } catch (error) {
        console.error("Error fetching categories:", error);
      }
    };
    fetchCategories();
  }, []);

  const handleCardClick = (product) => {
    setSelectedProduct(product);
    setShowModal(true);
  };

  const handleQuantityChange = (e) => {
    const value = parseFloat(e.target.value);
    if (!isNaN(value)) {
      setQuantity(value);
    }
  };

  const handleAddToCart = () => {
    if (selectedProduct) {
      addToCart(selectedProduct, quantity);
      handleClose();
      navigate('/cart');
    }
  };

  const handleClearSearch = () => {
    setSearchQuery("");
  };

  const handleSearchInputChange = (e) => {
    setSearchQuery(e.target.value);
  };

  const filteredCategories = categories.filter(category => {
    return category.title.toLowerCase().includes(searchQuery.toLowerCase()) || category.products.some(product => product.name.toLowerCase().includes(searchQuery.toLowerCase()));
  });

  return (
    <div style={{ backgroundColor: "orange", minHeight: "100vh", color: "#fff" }}>
      <Carousell />
      <br/><br/><br/>
      <Form.Group controlId="search">
        <div className="position-relative">
          <Form.Control
            type="text"
            placeholder="Search categories and products..."
            value={searchQuery}
            onChange={handleSearchInputChange}
          />
          {searchQuery && (
            <AiOutlineCloseCircle
              className="position-absolute"
              style={{ top: "50%", right: "10px", transform: "translateY(-50%)", cursor: "pointer" }}
              onClick={handleClearSearch}
            />
          )}
        </div>
      </Form.Group>
      <br/><br/><br/>
      <h2 style={{ textAlign: "left" }}>Categories</h2>
      <div className="card-container">
        <Row>
          {filteredCategories.map((category, index) => (
            <Col key={index} className="d-flex align-items-stretch">
              <Link
                to={`/products/${category.title}`}
                style={{ textDecoration: "none", color: "inherit" }}
              >
                <Card
                  style={{ width: "120px", height: "120px", marginBottom: "30px" }}
                >
                  <Card.Body>
                    <Card.Title style={{ fontSize: "15px", marginTop: "auto", marginBottom: "auto" }}>
                      {category.title}
                    </Card.Title>
                  </Card.Body>
                </Card>
              </Link>
            </Col>
          ))}
        </Row>
      </div>
      {/* Displaying products */}
      <Container fluid>
        {filteredCategories.map((category, categoryIndex) => (
          <div key={categoryIndex}>
            <h3 style={{ textAlign: "left" }}>{category.title}</h3>
            <div className="d-flex flex-wrap" style={{ overflow: "hidden", width: "100%" }}>
              {category.products.map((product) => (
                <Card
                  key={product.id}
                  className="m-3"
                  style={{
                    width: "115px",
                    height: "150px",
                    cursor: "pointer",
                    objectFit: "cover",
                    pointerEvents: "auto",
                    flex: "0 0 auto",
                  }}
                  onClick={() => handleCardClick(product)}
                >
                  <div style={{ width: "115px", height: "100px", overflow: "hidden" }}>
                    <Card.Img
                      variant="top"
                      src={product.imageUrl}
                      style={{ width: "100%", height: "100%", objectFit: "cover" }}
                    />
                  </div>
                  <Card.Body>
                    <Card.Title>
                      <p style={{ fontSize: "12px" }}>{product.name}</p>
                    </Card.Title>
                  </Card.Body>
                </Card>
              ))}
            </div>
          </div>
        ))}
      </Container>
      {/* Modal */}
      <Modal show={showModal} onHide={handleClose}>
        <Modal.Header closeButton>
          <Modal.Title>{selectedProduct && selectedProduct.name}</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <img
            src={selectedProduct && selectedProduct.imageUrl}
            alt={selectedProduct && selectedProduct.name}
            style={{ width: "80%", marginBottom: "20px" }}
          />
          <Form.Group controlId="quantity">
            <Form.Label>Quantity</Form.Label>
            <Form.Control
              type="number"
              value={quantity}
              onChange={handleQuantityChange}
              step="0.25"
              min="0"
            />
            (kg or g) (ml or l) (pack)
          </Form.Group>
          <p>
            Price: Rs.
            {selectedProduct &&
              (selectedProduct.price * quantity).toFixed(2)}
          </p>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={handleClose}>
            Close
          </Button>
          <Button variant="primary" onClick={handleAddToCart}>
            Add to Cart
          </Button>
        </Modal.Footer>
      </Modal>
      <Footer/>
    </div>
  );
}
