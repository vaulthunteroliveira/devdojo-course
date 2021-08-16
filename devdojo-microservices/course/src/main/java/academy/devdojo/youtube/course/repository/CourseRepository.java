package academy.devdojo.youtube.course.repository;

import org.springframework.data.repository.PagingAndSortingRepository;

import academy.devdojo.youtube.course.model.Course;

public interface CourseRepository extends PagingAndSortingRepository<Course, Long>{

	
}
