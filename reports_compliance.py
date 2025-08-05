from reports import ReportGenerator
from models import *
from datetime import datetime, timedelta
from sqlalchemy import func, and_, or_, desc
from decimal import Decimal

class ComplianceReportGenerator(ReportGenerator):
    """Handles all compliance, audit and custom reports"""
    
    @staticmethod
    def generate_stock_audit_report(start_date, end_date, category_id=None, supplier_id=None):
        """Generate stock audit report"""
        # Get all products with their current stock levels
        query = db.session.query(
            Product,
            Category.name.label('category_name'),
            Supplier.name.label('supplier_name')
        ).join(Category).outerjoin(Supplier)
        
        if category_id and int(category_id) > 0:
            query = query.filter(Product.category_id == category_id)
        if supplier_id and int(supplier_id) > 0:
            query = query.filter(Product.supplier_id == supplier_id)
            
        products = query.all()
        
        result = []
        for product, category_name, supplier_name in products:
            # Get stock movements for audit trail
            movements = StockMovement.query.filter_by(product_id=product.id).order_by(StockMovement.created_at.desc()).limit(5).all()
            
            product_dict = ReportGenerator.convert_to_dict(product)
            product_dict['category_name'] = category_name
            product_dict['supplier_name'] = supplier_name or "No Supplier"
            product_dict['stock_value'] = float(product.price) * product.quantity_in_stock
            product_dict['last_movement'] = movements[0].created_at if movements else product.created_at
            product_dict['movement_count'] = len(movements)
            
            result.append(product_dict)
        
        return result
    
    @staticmethod
    def generate_user_activity_report(start_date, end_date, user_id=None, activity_type='all'):
        """Generate user activity logs report"""
        start_dt = ReportGenerator.format_date(start_date)
        end_dt = ReportGenerator.format_date(end_date) + timedelta(days=1)
        
        # Get stock movements as activity logs
        query = db.session.query(
            StockMovement,
            Product.name.label('product_name'),
            User.username.label('user_name')
        ).join(Product).outerjoin(User, StockMovement.created_by == User.id)
        
        query = query.filter(StockMovement.created_at.between(start_dt, end_dt))
        
        if user_id and int(user_id) > 0:
            query = query.filter(StockMovement.created_by == user_id)
            
        movements = query.order_by(StockMovement.created_at.desc()).all()
        
        result = []
        for movement, product_name, user_name in movements:
            activity_dict = ReportGenerator.convert_to_dict(movement)
            activity_dict['product_name'] = product_name
            activity_dict['user_name'] = user_name or "System"
            activity_dict['activity_type'] = f"Stock {movement.movement_type}"
            activity_dict['description'] = f"{movement.movement_type} {movement.quantity} units of {product_name}"
            
            result.append(activity_dict)
        
        return result
    
    @staticmethod
    def generate_price_changes_report(start_date, end_date, product_id=None):
        """Generate price change history report"""
        # This would track price changes if we had a price history table
        # For now, we'll return current product prices
        query = db.session.query(
            Product,
            Category.name.label('category_name')
        ).join(Category)
        
        if product_id and int(product_id) > 0:
            query = query.filter(Product.id == product_id)
            
        products = query.all()
        
        result = []
        for product, category_name in products:
            product_dict = ReportGenerator.convert_to_dict(product)
            product_dict['category_name'] = category_name
            product_dict['margin'] = float(product.price - product.cost)
            product_dict['margin_percentage'] = float((product.price - product.cost) / product.cost * 100) if product.cost else 0
            
            result.append(product_dict)
        
        return result
    
    @staticmethod
    def generate_tax_report(start_date, end_date):
        """Generate tax calculation report"""
        start_dt = ReportGenerator.format_date(start_date)
        end_dt = ReportGenerator.format_date(end_date) + timedelta(days=1)
        
        # Get sales for tax reporting
        sales = db.session.query(
            Sale,
            Customer.first_name.label('customer_first_name'),
            Customer.last_name.label('customer_last_name')
        ).join(Customer).filter(Sale.sale_date.between(start_dt, end_dt)).all()
        
        result = []
        total_tax = Decimal('0.00')
        
        for sale, customer_first_name, customer_last_name in sales:
            sale_dict = ReportGenerator.convert_to_dict(sale)
            sale_dict['customer_name'] = f"{customer_first_name} {customer_last_name}"
            
            # Calculate tax (assuming 8.5% tax rate)
            tax_rate = Decimal('0.085')
            calculated_tax = sale.subtotal * tax_rate
            sale_dict['calculated_tax'] = calculated_tax
            total_tax += calculated_tax
            
            result.append(sale_dict)
        
        # Add summary row
        summary = {
            'sale_number': 'TOTAL',
            'customer_name': '',
            'subtotal': sum(float(sale.subtotal or 0) for sale, _, _ in sales),
            'tax_amount': float(total_tax),
            'total_amount': sum(float(sale.total_amount or 0) for sale, _, _ in sales)
        }
        result.append(summary)
        
        return result
    
    @staticmethod
    def generate_custom_report(start_date, end_date, report_config=None):
        """Generate custom report based on configuration"""
        # This is a flexible report generator that can be customized
        # For now, we'll return a comprehensive business summary
        
        start_dt = ReportGenerator.format_date(start_date)
        end_dt = ReportGenerator.format_date(end_date) + timedelta(days=1)
        
        # Get comprehensive business data
        total_products = Product.query.filter_by(is_active=True).count()
        total_customers = Customer.query.filter_by(is_active=True).count()
        total_sales = Sale.query.filter(Sale.sale_date.between(start_dt, end_dt)).count()
        total_revenue = db.session.query(func.sum(Sale.total_amount)).filter(Sale.sale_date.between(start_dt, end_dt)).scalar() or 0
        
        # Low stock items
        low_stock_count = Product.query.filter(Product.quantity_in_stock <= Product.reorder_level).count()
        
        # Top selling products
        top_products = db.session.query(
            Product.name,
            func.sum(SaleItem.quantity).label('total_sold')
        ).join(SaleItem).join(Sale).filter(Sale.sale_date.between(start_dt, end_dt)).group_by(Product.name).order_by(func.sum(SaleItem.quantity).desc()).limit(5).all()
        
        result = [{
            'metric': 'Total Active Products',
            'value': total_products,
            'category': 'Inventory'
        }, {
            'metric': 'Total Active Customers',
            'value': total_customers,
            'category': 'Customers'
        }, {
            'metric': 'Total Sales (Period)',
            'value': total_sales,
            'category': 'Sales'
        }, {
            'metric': 'Total Revenue (Period)',
            'value': float(total_revenue),
            'category': 'Sales'
        }, {
            'metric': 'Low Stock Items',
            'value': low_stock_count,
            'category': 'Inventory'
        }]
        
        # Add top products
        for i, (product_name, total_sold) in enumerate(top_products, 1):
            result.append({
                'metric': f'Top Product #{i}',
                'value': f"{product_name} ({total_sold} sold)",
                'category': 'Products'
            })
        
        return result