package academy.devdojo.youtube.repository;

import org.springframework.data.repository.PagingAndSortingRepository;

import academy.devdojo.youtube.model.Course;

public interface CourseRepository  extends PagingAndSortingRepository<Course, Long>{

}
