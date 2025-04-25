import logging
from datetime import datetime
from flask import render_template, redirect, url_for, flash, request, abort
from sqlalchemy.exc import SQLAlchemyError

from app import db
from models import Task, Category
from forms import TaskForm, CategoryForm

def register_routes(app):
    """Register all routes with the Flask application"""
    
    @app.context_processor
    def utility_processor():
        """Add utility functions to template context"""
        return {
            'now': datetime.utcnow
        }
    
    @app.route('/')
    def index():
        """Home page with task statistics"""
        total_tasks = Task.query.count()
        completed_tasks = Task.query.filter_by(completed=True).count()
        pending_tasks = total_tasks - completed_tasks
        
        # Get the most recent tasks
        recent_tasks = Task.query.order_by(Task.created_at.desc()).limit(5).all()
        
        # Count tasks by priority
        high_priority = Task.query.filter_by(priority=2, completed=False).count()
        medium_priority = Task.query.filter_by(priority=1, completed=False).count()
        low_priority = Task.query.filter_by(priority=0, completed=False).count()
        
        # Overdue tasks
        overdue_tasks = Task.query.filter(
            Task.due_date < datetime.utcnow(),
            Task.completed == False
        ).count()
        
        # Get category counts
        categories = Category.query.all()
        category_counts = []
        for category in categories:
            count = Task.query.filter_by(category_id=category.id).count()
            if count > 0:
                category_counts.append({
                    'name': category.name,
                    'count': count
                })
                
        return render_template('index.html', 
                            total_tasks=total_tasks,
                            completed_tasks=completed_tasks,
                            pending_tasks=pending_tasks,
                            high_priority=high_priority,
                            medium_priority=medium_priority,
                            low_priority=low_priority,
                            overdue_tasks=overdue_tasks,
                            recent_tasks=recent_tasks,
                            category_counts=category_counts)

    @app.route('/tasks')
    def tasks():
        """View all tasks with filtering options"""
        # Handle filter parameters
        status_filter = request.args.get('status', 'all')
        priority_filter = request.args.get('priority', 'all')
        category_filter = request.args.get('category', 'all')
        
        # Start with base query
        task_query = Task.query
        
        # Apply filters
        if status_filter == 'pending':
            task_query = task_query.filter_by(completed=False)
        elif status_filter == 'completed':
            task_query = task_query.filter_by(completed=True)
            
        if priority_filter != 'all' and priority_filter.isdigit():
            task_query = task_query.filter_by(priority=int(priority_filter))
            
        if category_filter != 'all' and category_filter.isdigit():
            task_query = task_query.filter_by(category_id=int(category_filter))
            
        # Sort by due date (null values last) and then by priority
        tasks = task_query.order_by(
            Task.completed.asc(),
            Task.due_date.asc().nulls_last(),
            Task.priority.desc()
        ).all()
        
        # Get all categories for the filter dropdown
        categories = Category.query.order_by(Category.name).all()
        
        return render_template('tasks.html', tasks=tasks, categories=categories,
                            current_status=status_filter,
                            current_priority=priority_filter,
                            current_category=category_filter)

    @app.route('/task/add', methods=['GET', 'POST'])
    def add_task():
        """Add a new task"""
        form = TaskForm()
        
        if form.validate_on_submit():
            try:
                # Create new task
                new_task = Task(
                    title=form.title.data,
                    description=form.description.data,
                    due_date=form.due_date.data,
                    completed=form.completed.data,
                    priority=form.priority.data,
                )
                
                # Handle the category - if 0 is selected, set to None
                if form.category_id.data > 0:
                    new_task.category_id = form.category_id.data
                
                db.session.add(new_task)
                db.session.commit()
                flash('Task added successfully!', 'success')
                return redirect(url_for('tasks'))
            except SQLAlchemyError as e:
                db.session.rollback()
                flash(f'Error adding task: {str(e)}', 'danger')
                logging.error(f"Database error: {str(e)}")
                
        return render_template('add_task.html', form=form)

    @app.route('/task/edit/<int:task_id>', methods=['GET', 'POST'])
    def edit_task(task_id):
        """Edit an existing task"""
        task = Task.query.get_or_404(task_id)
        
        # Pre-populate form with existing task data
        form = TaskForm(obj=task)
        
        if form.validate_on_submit():
            try:
                # Update task with form data
                task.title = form.title.data
                task.description = form.description.data
                task.due_date = form.due_date.data
                task.completed = form.completed.data
                task.priority = form.priority.data
                
                # Handle the category - if 0 is selected, set to None
                if form.category_id.data > 0:
                    task.category_id = form.category_id.data
                else:
                    task.category_id = None
                
                db.session.commit()
                flash('Task updated successfully!', 'success')
                return redirect(url_for('tasks'))
            except SQLAlchemyError as e:
                db.session.rollback()
                flash(f'Error updating task: {str(e)}', 'danger')
                logging.error(f"Database error: {str(e)}")
                
        return render_template('edit_task.html', form=form, task=task)

    @app.route('/task/delete/<int:task_id>')
    def delete_task(task_id):
        """Delete a task"""
        task = Task.query.get_or_404(task_id)
        
        try:
            db.session.delete(task)
            db.session.commit()
            flash('Task deleted successfully!', 'success')
        except SQLAlchemyError as e:
            db.session.rollback()
            flash(f'Error deleting task: {str(e)}', 'danger')
            logging.error(f"Database error: {str(e)}")
            
        return redirect(url_for('tasks'))

    @app.route('/task/toggle/<int:task_id>')
    def toggle_task_status(task_id):
        """Toggle task completion status"""
        task = Task.query.get_or_404(task_id)
        
        try:
            # Toggle the completed status
            task.completed = not task.completed
            db.session.commit()
            flash(f'Task marked as {"completed" if task.completed else "pending"}!', 'success')
        except SQLAlchemyError as e:
            db.session.rollback()
            flash(f'Error updating task status: {str(e)}', 'danger')
            logging.error(f"Database error: {str(e)}")
            
        return redirect(url_for('tasks'))

    @app.route('/categories')
    def categories():
        """View all categories"""
        categories = Category.query.order_by(Category.name).all()
        
        # For each category, count the number of tasks
        for category in categories:
            category.task_count = Task.query.filter_by(category_id=category.id).count()
            category.completed_count = Task.query.filter_by(category_id=category.id, completed=True).count()
            
        return render_template('categories.html', categories=categories)

    @app.route('/category/add', methods=['GET', 'POST'])
    def add_category():
        """Add a new category"""
        form = CategoryForm()
        
        if form.validate_on_submit():
            try:
                new_category = Category(
                    name=form.name.data,
                    description=form.description.data
                )
                
                db.session.add(new_category)
                db.session.commit()
                flash('Category added successfully!', 'success')
                return redirect(url_for('categories'))
            except SQLAlchemyError as e:
                db.session.rollback()
                flash(f'Error adding category: {str(e)}', 'danger')
                logging.error(f"Database error: {str(e)}")
                
        return render_template('add_category.html', form=form)

    @app.route('/category/edit/<int:category_id>', methods=['GET', 'POST'])
    def edit_category(category_id):
        """Edit an existing category"""
        category = Category.query.get_or_404(category_id)
        
        # Pre-populate form with existing category data
        form = CategoryForm(obj=category)
        
        if form.validate_on_submit():
            try:
                category.name = form.name.data
                category.description = form.description.data
                
                db.session.commit()
                flash('Category updated successfully!', 'success')
                return redirect(url_for('categories'))
            except SQLAlchemyError as e:
                db.session.rollback()
                flash(f'Error updating category: {str(e)}', 'danger')
                logging.error(f"Database error: {str(e)}")
                
        return render_template('edit_category.html', form=form, category=category)

    @app.route('/category/delete/<int:category_id>')
    def delete_category(category_id):
        """Delete a category and all associated tasks"""
        category = Category.query.get_or_404(category_id)
        
        try:
            db.session.delete(category)
            db.session.commit()
            flash('Category and all its tasks deleted successfully!', 'success')
        except SQLAlchemyError as e:
            db.session.rollback()
            flash(f'Error deleting category: {str(e)}', 'danger')
            logging.error(f"Database error: {str(e)}")
            
        return redirect(url_for('categories'))

    @app.errorhandler(404)
    def page_not_found(e):
        """Handle 404 errors"""
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        """Handle 500 errors"""
        return render_template('500.html'), 500